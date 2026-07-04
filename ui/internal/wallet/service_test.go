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

	txInfo      map[string]chain.TxInfo
	txInfoErrs  map[string]error
	txUTxOs     map[string]chain.TxUTxOs
	txUTxOErrs  map[string]error
	latestBlock chain.BlockTip
	latestErr   error
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

func (f *fakeChain) Transaction(_ context.Context, hash string) (chain.TxInfo, error) {
	if err := f.txInfoErrs[hash]; err != nil {
		return chain.TxInfo{}, err
	}
	return f.txInfo[hash], nil
}

func (f *fakeChain) TransactionUTxOs(_ context.Context, hash string) (chain.TxUTxOs, error) {
	if err := f.txUTxOErrs[hash]; err != nil {
		return chain.TxUTxOs{}, err
	}
	return f.txUTxOs[hash], nil
}

func (f *fakeChain) LatestBlock(_ context.Context) (chain.BlockTip, error) {
	return f.latestBlock, f.latestErr
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

func TestServiceTransactionsEnriched(t *testing.T) {
	fc := &fakeChain{
		addresses: []string{"addr_test1a"},
		txs: map[string][]chain.AddressTx{
			"addr_test1a": {{TxHash: "tx1", TxIndex: 0, BlockHeight: 90, BlockTime: 1000}},
		},
		txInfo: map[string]chain.TxInfo{
			"tx1": {Hash: "tx1", BlockHeight: 90, BlockTime: 1000, Fees: "170000"},
		},
		txUTxOs: map[string]chain.TxUTxOs{
			"tx1": {
				Hash:   "tx1",
				Inputs: []chain.TxIO{{Address: "addr_test1other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}}},
				Outputs: []chain.TxIO{
					{Address: "addr_test1a", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}}},
					{Address: "addr_test1other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "1830000"}}},
				},
			},
		},
		latestBlock: chain.BlockTip{Height: 100},
	}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 1); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	txs, err := s.Transactions(context.Background())
	if err != nil {
		t.Fatalf("Transactions: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("got %d txs, want 1", len(txs))
	}
	tx := txs[0]
	if tx.Direction != TxDirectionReceived {
		t.Fatalf("direction = %v, want received", tx.Direction)
	}
	if tx.NetLovelace != "3000000" {
		t.Fatalf("net = %v, want 3000000", tx.NetLovelace)
	}
	if tx.Fee != "170000" {
		t.Fatalf("fee = %v, want 170000", tx.Fee)
	}
	if tx.Confirmations != 10 || tx.Pending {
		t.Fatalf("confirmations = %d pending=%v, want 10 false", tx.Confirmations, tx.Pending)
	}
}

func TestServiceTransactionsEnrichmentNotFoundGraceful(t *testing.T) {
	// A transaction the node no longer has a record of (e.g. pruned under
	// lean-node history-expiry) must not fail the whole history — it keeps
	// its basic (hash/block) fields with enrichment left zero-valued.
	fc := &fakeChain{
		addresses: []string{"addr_test1a"},
		txs: map[string][]chain.AddressTx{
			"addr_test1a": {{TxHash: "tx-pruned", TxIndex: 0, BlockHeight: 50, BlockTime: 500}},
		},
		txInfoErrs:  map[string]error{"tx-pruned": chain.ErrNotFound},
		latestBlock: chain.BlockTip{Height: 100},
	}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 1); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	txs, err := s.Transactions(context.Background())
	if err != nil {
		t.Fatalf("Transactions: %v", err)
	}
	if len(txs) != 1 || txs[0].TxHash != "tx-pruned" {
		t.Fatalf("txs = %+v, want [tx-pruned]", txs)
	}
	if txs[0].Direction != "" || txs[0].Fee != "" {
		t.Fatalf("enrichment = %+v, want zero-valued (not found)", txs[0])
	}
	// Confirmations are computed from the already-known block height,
	// independent of the failed enrichment call.
	if txs[0].Confirmations != 50 || txs[0].Pending {
		t.Fatalf("confirmations = %d pending=%v, want 50 false", txs[0].Confirmations, txs[0].Pending)
	}
}

func TestServiceTransactionsFeePreservedWhenUTxOsPruned(t *testing.T) {
	// The tx summary (and its fee) can still be available even when the
	// node has pruned the UTxO-level detail for the same tx (lean-node
	// history-expiry can drop UTxO detail before the summary itself ages
	// out). The fee must not be silently discarded in that case.
	fc := &fakeChain{
		addresses: []string{"addr_test1a"},
		txs: map[string][]chain.AddressTx{
			"addr_test1a": {{TxHash: "tx1", TxIndex: 0, BlockHeight: 90, BlockTime: 1000}},
		},
		txInfo: map[string]chain.TxInfo{
			"tx1": {Hash: "tx1", BlockHeight: 90, BlockTime: 1000, Fees: "170000"},
		},
		txUTxOErrs:  map[string]error{"tx1": chain.ErrNotFound},
		latestBlock: chain.BlockTip{Height: 100},
	}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 1); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	txs, err := s.Transactions(context.Background())
	if err != nil {
		t.Fatalf("Transactions: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("got %d txs, want 1", len(txs))
	}
	if txs[0].Fee != "170000" {
		t.Fatalf("fee = %q, want 170000 (fee must survive a pruned UTxO-detail call)", txs[0].Fee)
	}
	if txs[0].Direction != "" {
		t.Fatalf("direction = %v, want empty (direction still requires UTxO detail)", txs[0].Direction)
	}
}

// TestServiceTransactionsRecognizesChangeAddressOwnership guards against
// treating a not-yet-discovered change address as external. scanAddresses'
// result (what mine used to be built from) only includes receive addresses
// plus whatever the node's account index has already reported; a change
// address the node hasn't seen a spend from yet is absent from it even
// though the wallet controls it.
func TestServiceTransactionsRecognizesChangeAddressOwnership(t *testing.T) {
	fc := &fakeChain{
		addresses: []string{"addr_test1a"},
		txs: map[string][]chain.AddressTx{
			"addr_test1a": {{TxHash: "tx1", TxIndex: 0, BlockHeight: 90, BlockTime: 1000}},
		},
		txInfo: map[string]chain.TxInfo{
			"tx1": {Hash: "tx1", BlockHeight: 90, BlockTime: 1000, Fees: "200000"},
		},
		latestBlock: chain.BlockTip{Height: 100},
	}
	s := NewService(fc)
	acct, err := s.SetWallet(testMnemonic, "preview", 1)
	if err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	if len(acct.ChangeAddresses) == 0 {
		t.Fatalf("account has no change addresses")
	}
	changeAddr := acct.ChangeAddresses[0]

	// The wallet spends a discovered address entirely into its own
	// not-yet-discovered change address: an internal consolidation, not a
	// payment to or from an outside party.
	fc.txUTxOs = map[string]chain.TxUTxOs{
		"tx1": {
			Hash:    "tx1",
			Inputs:  []chain.TxIO{{Address: "addr_test1a", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}}},
			Outputs: []chain.TxIO{{Address: changeAddr, Amount: []chain.Amount{{Unit: "lovelace", Quantity: "4800000"}}}},
		},
	}
	txs, err := s.Transactions(context.Background())
	if err != nil {
		t.Fatalf("Transactions: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("got %d txs, want 1", len(txs))
	}
	if txs[0].Direction != TxDirectionSelf {
		t.Fatalf("direction = %v, want self (change address must count as the wallet's own)", txs[0].Direction)
	}
	if txs[0].NetLovelace != "-200000" {
		t.Fatalf("net = %v, want -200000 (fee only)", txs[0].NetLovelace)
	}
}

func TestServiceTransactionDetail(t *testing.T) {
	fc := &fakeChain{
		addresses: []string{"addr_test1a"},
		txInfo: map[string]chain.TxInfo{
			"tx1": {Hash: "tx1", BlockHeight: 90, BlockTime: 1000, Fees: "170000", Index: 2},
		},
		txUTxOs: map[string]chain.TxUTxOs{
			"tx1": {
				Hash:   "tx1",
				Inputs: []chain.TxIO{{Address: "addr_test1a", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}}},
				Outputs: []chain.TxIO{
					{Address: "addr_test1other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}}},
					{Address: "addr_test1a", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "1830000"}}},
				},
			},
		},
		latestBlock: chain.BlockTip{Height: 95},
	}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 1); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	detail, err := s.TransactionDetail(context.Background(), "tx1")
	if err != nil {
		t.Fatalf("TransactionDetail: %v", err)
	}
	if detail.TxHash != "tx1" || detail.TxIndex != 2 {
		t.Fatalf("tx summary = %+v", detail.Tx)
	}
	if detail.Direction != TxDirectionSent {
		t.Fatalf("direction = %v, want sent", detail.Direction)
	}
	if detail.NetLovelace != "-3170000" {
		t.Fatalf("net = %v, want -3170000", detail.NetLovelace)
	}
	if detail.Fee != "170000" {
		t.Fatalf("fee = %v, want 170000", detail.Fee)
	}
	if detail.Confirmations != 5 {
		t.Fatalf("confirmations = %d, want 5", detail.Confirmations)
	}
	if len(detail.Inputs) != 1 || !detail.Inputs[0].IsMine || detail.Inputs[0].Lovelace != "5000000" {
		t.Fatalf("inputs = %+v", detail.Inputs)
	}
	if len(detail.Outputs) != 2 {
		t.Fatalf("outputs = %+v", detail.Outputs)
	}
	var sawExternal, sawMine bool
	for _, o := range detail.Outputs {
		if o.IsMine {
			sawMine = true
			if o.Lovelace != "1830000" {
				t.Fatalf("mine output lovelace = %v, want 1830000", o.Lovelace)
			}
		} else {
			sawExternal = true
			if o.Lovelace != "3000000" {
				t.Fatalf("external output lovelace = %v, want 3000000", o.Lovelace)
			}
		}
	}
	if !sawMine || !sawExternal {
		t.Fatalf("expected one mine + one external output, got %+v", detail.Outputs)
	}
}

func TestServiceTransactionDetailNoWallet(t *testing.T) {
	s := NewService(&fakeChain{})
	if _, err := s.TransactionDetail(context.Background(), "tx1"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("TransactionDetail without wallet: err = %v, want ErrNoWallet", err)
	}
}

func TestServiceTransactionDetailNotFound(t *testing.T) {
	fc := &fakeChain{txInfoErrs: map[string]error{"unknown": chain.ErrNotFound}}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 1); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	if _, err := s.TransactionDetail(context.Background(), "unknown"); !errors.Is(err, chain.ErrNotFound) {
		t.Fatalf("TransactionDetail unknown hash: err = %v, want chain.ErrNotFound", err)
	}
}

func TestServiceTransactionDetailSelfTransfer(t *testing.T) {
	// Every input and output belongs to the wallet's own addresses: a
	// consolidation/self-transfer, not a payment to or from anyone else.
	fc := &fakeChain{
		addresses: []string{"addr_test1a", "addr_test1b"},
		txInfo: map[string]chain.TxInfo{
			"tx1": {Hash: "tx1", BlockHeight: 10, Fees: "170000"},
		},
		txUTxOs: map[string]chain.TxUTxOs{
			"tx1": {
				Hash:    "tx1",
				Inputs:  []chain.TxIO{{Address: "addr_test1a", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}}},
				Outputs: []chain.TxIO{{Address: "addr_test1b", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "4830000"}}}},
			},
		},
		latestBlock: chain.BlockTip{Height: 10},
	}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 1); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	detail, err := s.TransactionDetail(context.Background(), "tx1")
	if err != nil {
		t.Fatalf("TransactionDetail: %v", err)
	}
	if detail.Direction != TxDirectionSelf {
		t.Fatalf("direction = %v, want self", detail.Direction)
	}
	if detail.NetLovelace != "-170000" {
		t.Fatalf("net = %v, want -170000 (fee only)", detail.NetLovelace)
	}
}

func TestServiceTransactionsTipLookupFailureDegradesGracefully(t *testing.T) {
	// A LatestBlock failure must not fail the whole history endpoint — the
	// already-merged, already-enriched list is still valid; only the
	// confirmation count relative to the tip is unknowable.
	fc := &fakeChain{
		addresses: []string{"addr_test1a"},
		txs: map[string][]chain.AddressTx{
			"addr_test1a": {{TxHash: "tx1", TxIndex: 0, BlockHeight: 90, BlockTime: 1000}},
		},
		txInfo: map[string]chain.TxInfo{
			"tx1": {Hash: "tx1", BlockHeight: 90, BlockTime: 1000, Fees: "170000"},
		},
		txUTxOs: map[string]chain.TxUTxOs{
			"tx1": {
				Hash: "tx1",
				Outputs: []chain.TxIO{
					{Address: "addr_test1a", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}}},
				},
			},
		},
		latestErr: errors.New("tip lookup boom"),
	}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 1); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	txs, err := s.Transactions(context.Background())
	if err != nil {
		t.Fatalf("Transactions: %v, want no error (tip failure must degrade)", err)
	}
	if len(txs) != 1 {
		t.Fatalf("got %d txs, want 1", len(txs))
	}
	tx := txs[0]
	if !tx.Pending || tx.Confirmations != 0 {
		t.Fatalf("confirmations = %d pending=%v, want 0/pending (tip unknown)", tx.Confirmations, tx.Pending)
	}
	// Per-tx enrichment (direction/fee) is unaffected by the tip failure.
	if tx.Direction != TxDirectionReceived || tx.Fee != "170000" {
		t.Fatalf("enrichment = %+v, want direction=received fee=170000 despite tip failure", tx)
	}
}

func TestServiceTransactionDetailTipLookupFailureDoesNotNotFound(t *testing.T) {
	// A tip-lookup failure (even chain.ErrNotFound) must not turn a
	// found transaction into a 404: serve() maps chain.ErrNotFound to 404,
	// which would misreport a tx that genuinely exists.
	fc := &fakeChain{
		addresses: []string{"addr_test1a"},
		txInfo: map[string]chain.TxInfo{
			"tx1": {Hash: "tx1", BlockHeight: 90, Fees: "170000"},
		},
		txUTxOs: map[string]chain.TxUTxOs{
			"tx1": {
				Hash:   "tx1",
				Inputs: []chain.TxIO{{Address: "addr_test1a", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}}},
				Outputs: []chain.TxIO{
					{Address: "addr_test1other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "4830000"}}},
				},
			},
		},
		latestErr: chain.ErrNotFound,
	}
	s := NewService(fc)
	if _, err := s.SetWallet(testMnemonic, "preview", 1); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	detail, err := s.TransactionDetail(context.Background(), "tx1")
	if err != nil {
		t.Fatalf("TransactionDetail: %v, want no error (tip failure must not 404 a found tx)", err)
	}
	if detail.TxHash != "tx1" {
		t.Fatalf("tx hash = %v, want tx1", detail.TxHash)
	}
	if !detail.Pending || detail.Confirmations != 0 {
		t.Fatalf("confirmations = %d pending=%v, want 0/pending (tip unknown)", detail.Confirmations, detail.Pending)
	}
	if detail.Direction != TxDirectionSent {
		t.Fatalf("direction = %v, want sent (unaffected by tip failure)", detail.Direction)
	}
}
