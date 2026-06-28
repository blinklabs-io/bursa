// Package wallet derives a read-only CIP-1852 account and aggregates its
// on-chain state (queried by stake credential) into balance, address, and
// history views. It holds no private keys beyond what derivation requires
// in-process and performs no signing.
package wallet

import (
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// Account is a derived, read-only view of a wallet: its stake address (the
// query key) and a window of external (receive) payment addresses, all sharing
// the canonical stake key at index 0.
//
// DRepKeyHash is the wallet's own DRep verification-key hash (CIP-0105,
// derivation role 3), derived at the same time as the addresses. It carries the
// public credential (a 28-byte blake2b-224 digest, hex-encoded over JSON) for
// self-DRep registration and self vote delegation, so those operations need no
// password to learn the wallet's DRep identity. It is public material, not a key.
type Account struct {
	Network          string   `json:"network"`
	StakeAddress     string   `json:"stake_address"`
	ReceiveAddresses []string `json:"receive_addresses"`
	DRepKeyHash      []byte   `json:"drep_key_hash,omitempty"`
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
	root, err := rootKeyFromMnemonicBytes(mnemonic)
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
// stake address plus windowN external receive addresses (indices 0..windowN-1),
// all bound to the canonical stake key m/1852'/1815'/0'/2/0.
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
	root, err := rootKeyFromMnemonicBytes(mnemonic)
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
	drepHash := drepKey.Public().PublicKey().Hash()

	stakeAddr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, netID, nil, stakeHash)
	if err != nil {
		return nil, fmt.Errorf("stake address: %w", err)
	}

	receive := make([]string, 0, windowN)
	for i := 0; i < windowN; i++ {
		payKey, err := bursa.GetPaymentKey(acctKey, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("payment key %d: %w", i, err)
		}
		payHash := payKey.Public().PublicKey().Hash()
		zeroXPrv(payKey)
		addr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeKeyKey, netID, payHash, stakeHash)
		if err != nil {
			return nil, fmt.Errorf("address %d: %w", i, err)
		}
		receive = append(receive, addr.String())
	}

	return &Account{
		Network:          network,
		StakeAddress:     stakeAddr.String(),
		ReceiveAddresses: receive,
		DRepKeyHash:      drepHash,
	}, nil
}

func zeroXPrv(key bip32.XPrv) {
	for i := range key {
		key[i] = 0
	}
}
