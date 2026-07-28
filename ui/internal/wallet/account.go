// Package wallet derives a read-only CIP-1852 account and aggregates its
// on-chain state (queried by stake credential) into balance, address, and
// history views. It holds no private keys beyond what derivation requires
// in-process and performs no signing.
package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Account is a derived, read-only view of a wallet: its stake address (the
// query key) plus windows of external (receive) and internal (change) payment
// addresses, all sharing the canonical stake key at index 0.
//
// DRepKeyHash is the wallet's own DRep verification-key hash (CIP-0105,
// derivation role 3), derived at the same time as the addresses. It carries the
// public credential (a 28-byte blake2b-224 digest, hex-encoded over JSON) for
// self-DRep registration and self vote delegation, so those operations need no
// password to learn the wallet's DRep identity. It is public material, not a key.
type Account struct {
	Network string `json:"network"`
	// AccountIndex is the hardened CIP-1852 account component used to derive
	// this account-level key (m/1852'/1815'/<account>').
	AccountIndex     uint32   `json:"account_index"`
	StakeAddress     string   `json:"stake_address"`
	ReceiveAddresses []string `json:"receive_addresses"`
	DRepKeyHash      string   `json:"drep_key_hash,omitempty"`
	ChangeAddresses  []string `json:"change_addresses,omitempty"`
}

// AccountXpub returns the Bech32-encoded extended public key for the CIP-1852
// account m/1852'/1815'/0' derived from the mnemonic. It is stored in the vault
// index as a stable account identifier and for any future xpub-based read-only
// derivation; the account-level xpub never reveals a spending key.
func AccountXpub(mnemonic string) (string, error) {
	root, err := bursa.GetRootKeyFromMnemonic(mnemonic, "")
	if err != nil {
		return "", fmt.Errorf("root key from mnemonic: %w", err)
	}
	return accountXpubFromRoot(root)
}

// AccountXpubFromMnemonicBytes is the zeroable-byte variant of AccountXpub.
func AccountXpubFromMnemonicBytes(mnemonic []byte) (string, error) {
	root, err := RootKeyFromMnemonicBytes(mnemonic)
	if err != nil {
		return "", fmt.Errorf("root key from mnemonic: %w", err)
	}
	return accountXpubFromRoot(root)
}

func accountXpubFromRoot(root bip32.XPrv) (string, error) {
	defer zeroXPrv(root)
	acctKey, err := bursa.GetAccountKey(root, 0)
	if err != nil {
		return "", fmt.Errorf("account key: %w", err)
	}
	defer zeroXPrv(acctKey)
	return acctKey.Public().String(), nil
}

// Derive builds the account for the given mnemonic and network, producing the
// stake address plus windowN external receive addresses and windowN internal
// change addresses (indices 0..windowN-1), all bound to the canonical stake key
// m/1852'/1815'/0'/2/0.
func Derive(mnemonic, network string, windowN int) (*Account, error) {
	netID, err := validateDeriveInputs(network, windowN)
	if err != nil {
		return nil, err
	}
	root, err := bursa.GetRootKeyFromMnemonic(mnemonic, "")
	if err != nil {
		return nil, fmt.Errorf("root key from mnemonic: %w", err)
	}
	return deriveFromRoot(root, network, netID, windowN)
}

// DeriveFromMnemonicBytes is the zeroable-byte variant of Derive.
func DeriveFromMnemonicBytes(mnemonic []byte, network string, windowN int) (*Account, error) {
	netID, err := validateDeriveInputs(network, windowN)
	if err != nil {
		return nil, err
	}
	root, err := RootKeyFromMnemonicBytes(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("root key from mnemonic: %w", err)
	}
	return deriveFromRoot(root, network, netID, windowN)
}

func validateDeriveInputs(network string, windowN int) (uint8, error) {
	if windowN < 1 {
		return 0, fmt.Errorf("windowN must be at least 1, got %d", windowN)
	}
	netID, err := cardanonet.AddressNetworkID(network)
	if err != nil {
		return 0, err
	}
	return netID, nil
}

func deriveFromRoot(root bip32.XPrv, network string, netID uint8, windowN int) (*Account, error) {
	defer zeroXPrv(root)
	acctKey, err := bursa.GetAccountKey(root, 0)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	defer zeroXPrv(acctKey)
	stakeKey, err := bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		return nil, fmt.Errorf("stake key: %w", err)
	}
	defer zeroXPrv(stakeKey)
	stakeHash := stakeKey.Public().PublicKey().Hash()

	// The wallet's own DRep credential (CIP-0105, role 3): a public key hash used
	// for self-DRep registration and self vote delegation.
	drepKey, err := bursa.GetDRepKey(acctKey, 0)
	if err != nil {
		return nil, fmt.Errorf("drep key: %w", err)
	}
	defer zeroXPrv(drepKey)
	drepHash := hex.EncodeToString(drepKey.Public().PublicKey().Hash())

	stakeAddr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, netID, nil, stakeHash)
	if err != nil {
		return nil, fmt.Errorf("stake address: %w", err)
	}

	deriveAddr := func(chain uint32, i int) (string, error) {
		idx := uint32(i) //nolint:gosec // i is bounded by the configured window size
		roleKey := acctKey.Derive(chain)
		defer zeroXPrv(roleKey)
		payKey := roleKey.Derive(idx)
		defer zeroXPrv(payKey)
		payHash := payKey.Public().PublicKey().Hash()
		addr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeKeyKey, netID, payHash, stakeHash)
		if err != nil {
			return "", err
		}
		return addr.String(), nil
	}

	receive := make([]string, 0, windowN)
	change := make([]string, 0, windowN)
	for i := 0; i < windowN; i++ {
		addr, err := deriveAddr(0, i)
		if err != nil {
			return nil, fmt.Errorf("receive address %d: %w", i, err)
		}
		receive = append(receive, addr)
		addr, err = deriveAddr(1, i)
		if err != nil {
			return nil, fmt.Errorf("change address %d: %w", i, err)
		}
		change = append(change, addr)
	}

	return &Account{
		Network:          network,
		StakeAddress:     stakeAddr.String(),
		ReceiveAddresses: receive,
		DRepKeyHash:      drepHash,
		ChangeAddresses:  change,
	}, nil
}

// DeriveFromAccountXpub derives a read-only Account from an account-level
// extended public key (Bech32-encoded, normally with the acct_xvk HRP; root_xvk
// is also accepted for compatibility with AccountXpub). This is the
// hardware-wallet path: no private key is required. The returned account is
// byte-identical to one produced by DeriveFromMnemonicBytes for the same key.
//
// Role mapping (CIP-1852):
//   - receive addresses: xpub.Derive(0).Derive(i) for i in 0..windowN-1
//   - change addresses:  xpub.Derive(1).Derive(i) for i in 0..windowN-1
//   - stake address:     xpub.Derive(2).Derive(0)
//   - DRep key hash:     xpub.Derive(3).Derive(0)
//
// The parent CIP-1852 account index is recorded on the returned Account. It
// cannot be recovered from the xpub itself, but is needed later to build the
// derivation paths a hardware device signs with.
func DeriveFromAccountXpub(accountXpubBech32, network string, accountIndex uint32, windowN int) (*Account, error) {
	const hardenedKeyStart = uint32(1 << 31)
	if accountIndex >= hardenedKeyStart {
		return nil, fmt.Errorf("account index must be less than %d, got %d", hardenedKeyStart, accountIndex)
	}
	netID, err := validateDeriveInputs(network, windowN)
	if err != nil {
		return nil, err
	}
	acctXpub, err := parseAccountXpub(accountXpubBech32)
	if err != nil {
		return nil, fmt.Errorf("decode account xpub: %w", err)
	}

	// Stake address: role 2, index 0
	stakeXpub, err := acctXpub.Derive(2)
	if err != nil {
		return nil, fmt.Errorf("derive stake role: %w", err)
	}
	stakeIndexXpub, err := stakeXpub.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("derive stake index: %w", err)
	}
	stakeHash := stakeIndexXpub.PublicKey().Hash()

	// DRep credential: role 3, index 0.
	drepXpub, err := acctXpub.Derive(3)
	if err != nil {
		return nil, fmt.Errorf("derive DRep role: %w", err)
	}
	drepIndexXpub, err := drepXpub.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("derive DRep index: %w", err)
	}
	drepHash := hex.EncodeToString(drepIndexXpub.PublicKey().Hash())

	stakeAddr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, netID, nil, stakeHash)
	if err != nil {
		return nil, fmt.Errorf("stake address: %w", err)
	}

	deriveAddresses := func(role uint32, label string) ([]string, error) {
		roleXpub, err := acctXpub.Derive(role)
		if err != nil {
			return nil, fmt.Errorf("derive %s role: %w", label, err)
		}
		addresses := make([]string, 0, windowN)
		for i := 0; i < windowN; i++ {
			indexXpub, err := roleXpub.Derive(uint32(i)) //nolint:gosec // i is bounded by windowN < MaxInt32 in practice
			if err != nil {
				return nil, fmt.Errorf("derive %s index %d: %w", label, i, err)
			}
			payHash := indexXpub.PublicKey().Hash()
			addr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeKeyKey, netID, payHash, stakeHash)
			if err != nil {
				return nil, fmt.Errorf("%s address %d: %w", label, i, err)
			}
			addresses = append(addresses, addr.String())
		}
		return addresses, nil
	}

	receive, err := deriveAddresses(0, "receive")
	if err != nil {
		return nil, err
	}
	change, err := deriveAddresses(1, "change")
	if err != nil {
		return nil, err
	}

	return &Account{
		Network:          network,
		AccountIndex:     accountIndex,
		StakeAddress:     stakeAddr.String(),
		ReceiveAddresses: receive,
		DRepKeyHash:      drepHash,
		ChangeAddresses:  change,
	}, nil
}

// parseAccountXpub accepts the standard account-key HRP emitted by hardware
// wallets as well as the root_xvk label historically emitted by AccountXpub.
// The HRP is only a Bech32 type label; both encodings carry the same 64-byte
// extended public key payload.
func parseAccountXpub(s string) (bip32.XPub, error) {
	hrp, decoded, err := bip32.LenientBech32Decode(s)
	if err != nil {
		return nil, err
	}
	if hrp != "acct_xvk" && hrp != "root_xvk" {
		return nil, errors.New("invalid HRP for account extended public key, expected acct_xvk or root_xvk")
	}
	converted, err := bech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(converted) != 64 {
		return nil, errors.New("invalid length for account extended public key, expected 64 bytes")
	}
	return bip32.XPub(converted), nil
}

func zeroXPrv(key bip32.XPrv) {
	for i := range key {
		key[i] = 0
	}
}
