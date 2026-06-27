// Package wallet derives a read-only CIP-1852 account and aggregates its
// on-chain state (queried by stake credential) into balance, address, and
// history views. It holds no private keys beyond what derivation requires
// in-process and performs no signing.
package wallet

import (
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/ui/internal/cardanonet"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// Account is a derived, read-only view of a wallet: its stake address (the
// query key) and a window of external (receive) payment addresses, all sharing
// the canonical stake key at index 0.
type Account struct {
	Network          string   `json:"network"`
	StakeAddress     string   `json:"stake_address"`
	ReceiveAddresses []string `json:"receive_addresses"`
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
	acctKey, err := bursa.GetAccountKey(root, 0)
	if err != nil {
		return "", fmt.Errorf("account key: %w", err)
	}
	return acctKey.Public().String(), nil
}

// Derive builds the account for the given mnemonic and network, producing the
// stake address plus windowN external receive addresses (indices 0..windowN-1),
// all bound to the canonical stake key m/1852'/1815'/0'/2/0.
func Derive(mnemonic, network string, windowN int) (*Account, error) {
	if windowN < 1 {
		return nil, fmt.Errorf("windowN must be at least 1, got %d", windowN)
	}
	netID, err := cardanonet.AddressNetworkID(network)
	if err != nil {
		return nil, err
	}

	root, err := bursa.GetRootKeyFromMnemonic(mnemonic, "")
	if err != nil {
		return nil, fmt.Errorf("root key from mnemonic: %w", err)
	}
	acctKey, err := bursa.GetAccountKey(root, 0)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	stakeKey, err := bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		return nil, fmt.Errorf("stake key: %w", err)
	}
	stakeHash := stakeKey.Public().PublicKey().Hash()

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
	}, nil
}
