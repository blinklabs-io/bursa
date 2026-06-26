package wallet

import (
	"context"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

type fakeChain struct {
	account      chain.AccountInfo
	accountErr   error
	addresses    []string
	addressesErr error
	utxos        map[string][]chain.UTxO
	utxoErrs     map[string]error
	txs          map[string][]chain.AddressTx
	txErrs       map[string]error
}

func (f *fakeChain) Account(_ context.Context, _ string) (chain.AccountInfo, error) {
	return f.account, f.accountErr
}

func (f *fakeChain) AccountAddresses(_ context.Context, _ string) ([]string, error) {
	return f.addresses, f.addressesErr
}

func (f *fakeChain) AddressUTxOs(_ context.Context, addr string) ([]chain.UTxO, error) {
	if err := f.utxoErrs[addr]; err != nil {
		return nil, err
	}
	return f.utxos[addr], nil
}

func (f *fakeChain) AddressTransactions(_ context.Context, addr string) ([]chain.AddressTx, error) {
	if err := f.txErrs[addr]; err != nil {
		return nil, err
	}
	return f.txs[addr], nil
}

func TestServiceNoWallet(t *testing.T) {
	s := NewService(&fakeChain{})
	if _, err := s.Balance(context.Background()); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("Balance without wallet: err = %v, want ErrNoWallet", err)
	}
}

func TestServiceBalanceAndAddresses(t *testing.T) {
	fc := &fakeChain{
		account:   chain.AccountInfo{ControlledAmount: "3000000"},
		addresses: []string{"addr_test1a"},
		utxos: map[string][]chain.UTxO{
			"addr_test1a": {{Amount: []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}}}},
		},
	}
	s := NewService(fc)
	acct, err := s.SetWallet(testMnemonic, "preview", 3)
	if err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	wantFirstReceive := acct.ReceiveAddresses[0]
	acct.ReceiveAddresses[0] = "addr_test1mutated_from_setwallet"
	bal, err := s.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal.Lovelace != "3000000" {
		t.Fatalf("lovelace = %q, want 3000000", bal.Lovelace)
	}
	av, err := s.Addresses(context.Background())
	if err != nil {
		t.Fatalf("Addresses: %v", err)
	}
	if len(av.Receive) != 3 {
		t.Fatalf("receive window = %d, want 3", len(av.Receive))
	}
	if av.Receive[0] != wantFirstReceive {
		t.Fatalf("receive[0] = %q, want %q", av.Receive[0], wantFirstReceive)
	}
	if len(av.Used) != 1 || av.Used[0] != "addr_test1a" {
		t.Fatalf("used = %v, want [addr_test1a]", av.Used)
	}
	if av.NextUnused == "" {
		t.Fatal("NextUnused empty, want a derived address")
	}
	wantNextUnused := av.NextUnused
	av.Receive[0] = "addr_test1mutated_receive"
	av.Used[0] = "addr_test1mutated_used"
	av.NextUnused = "addr_test1mutated_next"

	av, err = s.Addresses(context.Background())
	if err != nil {
		t.Fatalf("Addresses after caller mutation: %v", err)
	}
	if len(av.Receive) != 3 {
		t.Fatalf("receive window after caller mutation = %d, want 3", len(av.Receive))
	}
	if av.Receive[0] != wantFirstReceive {
		t.Fatalf("receive[0] after caller mutation = %q, want %q", av.Receive[0], wantFirstReceive)
	}
	if len(av.Used) != 1 || av.Used[0] != "addr_test1a" {
		t.Fatalf("used after caller mutation = %v, want [addr_test1a]", av.Used)
	}
	if av.NextUnused != wantNextUnused {
		t.Fatalf("NextUnused after caller mutation = %q, want %q", av.NextUnused, wantNextUnused)
	}
	bal, err = s.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance after caller mutation: %v", err)
	}
	if bal.Lovelace != "3000000" {
		t.Fatalf("lovelace after caller mutation = %q, want 3000000", bal.Lovelace)
	}
}

func TestServiceEmptyAccount(t *testing.T) {
	// A fresh/unknown stake credential: the node returns 404 (chain.ErrNotFound)
	// for the account and its addresses. Read-only views must treat this as an
	// empty wallet, not a hard error.
	fc := &fakeChain{accountErr: chain.ErrNotFound, addressesErr: chain.ErrNotFound}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 3); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	bal, err := s.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance on empty account: %v", err)
	}
	if bal.Lovelace != "0" || len(bal.Assets) != 0 {
		t.Fatalf("empty balance = %+v, want 0 / no assets", bal)
	}
	av, err := s.Addresses(context.Background())
	if err != nil {
		t.Fatalf("Addresses on empty account: %v", err)
	}
	if len(av.Used) != 0 {
		t.Fatalf("used = %v, want empty", av.Used)
	}
	if av.NextUnused != av.Receive[0] {
		t.Fatalf("NextUnused = %q, want receive[0] %q", av.NextUnused, av.Receive[0])
	}
	if _, err := s.Transactions(context.Background()); err != nil {
		t.Fatalf("Transactions on empty account: %v", err)
	}
	dv, err := s.Delegation(context.Background())
	if err != nil {
		t.Fatalf("Delegation on empty account: %v", err)
	}
	if dv.PoolID != nil || dv.Active || dv.RewardsSum != "0" || dv.Withdrawable != "0" {
		t.Fatalf("delegation on empty account = %+v, want not active / no pool / zero amounts", dv)
	}
}

func TestServiceIgnoresUnusedDerivedAddressNotFound(t *testing.T) {
	fc := &fakeChain{
		addresses: []string{"addr_test1used"},
		utxos: map[string][]chain.UTxO{
			"addr_test1used": {{Amount: []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}}}},
		},
		txs: map[string][]chain.AddressTx{
			"addr_test1used": {{TxHash: "tx-used", BlockHeight: 42}},
		},
	}
	s := NewService(fc)
	acct, err := s.SetWallet(testMnemonic, "preview", 3)
	if err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	fc.utxoErrs = map[string]error{
		acct.ReceiveAddresses[0]: chain.ErrNotFound,
		acct.ReceiveAddresses[1]: chain.ErrNotFound,
		acct.ReceiveAddresses[2]: chain.ErrNotFound,
	}
	fc.txErrs = map[string]error{
		acct.ReceiveAddresses[0]: chain.ErrNotFound,
		acct.ReceiveAddresses[1]: chain.ErrNotFound,
		acct.ReceiveAddresses[2]: chain.ErrNotFound,
	}

	bal, err := s.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal.Lovelace != "3000000" {
		t.Fatalf("lovelace = %q, want 3000000", bal.Lovelace)
	}
	txs, err := s.Transactions(context.Background())
	if err != nil {
		t.Fatalf("Transactions: %v", err)
	}
	if len(txs) != 1 || txs[0].TxHash != "tx-used" {
		t.Fatalf("transactions = %+v, want tx-used only", txs)
	}
}
