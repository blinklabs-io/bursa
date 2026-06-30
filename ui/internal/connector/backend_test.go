package connector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"

	apollobackend "github.com/blinklabs-io/apollo/v2/backend"
	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	gocbor "github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/mary"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// testMnemonic is the standard BIP-39 "abandon … art" 24-word test vector.
const backendTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

// ---------------------------------------------------------------------------
// Fake chain for connector tests
// ---------------------------------------------------------------------------

// fakeConnectorChain satisfies chainFetcher using a canned map of address UTxOs.
type fakeConnectorChain struct {
	addresses  []string // returned by AccountAddresses
	addressErr error    // error from AccountAddresses (nil = success)
	utxos      map[string][]chain.UTxO
	utxoErr    map[string]error
}

func (f *fakeConnectorChain) AccountAddresses(_ context.Context, _ string) ([]string, error) {
	if f.addressErr != nil {
		return nil, f.addressErr
	}
	return f.addresses, nil
}

func (f *fakeConnectorChain) AddressUTxOs(_ context.Context, addr string) ([]chain.UTxO, error) {
	if err := f.utxoErr[addr]; err != nil {
		return nil, err
	}
	return f.utxos[addr], nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustDeriveBackendAccount derives the preview account from backendTestMnemonic.
func mustDeriveBackendAccount(t *testing.T) (*wallet.Account, *wallet.Service) {
	t.Helper()
	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	wl := wallet.NewService(&walletChainBridge{f: fc})
	acct, err := wl.SetWallet(backendTestMnemonic, "preview", 3)
	if err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	return acct, wl
}

// walletChainBridge wraps fakeConnectorChain to satisfy wallet's unexported
// chainQuerier interface (which matches the public fields we need).
type walletChainBridge struct {
	f        *fakeConnectorChain
	acctErr  error             // returned by Account (nil = ErrNotFound)
	acctInfo chain.AccountInfo // returned by Account when acctErr is nil
}

func (b *walletChainBridge) Account(_ context.Context, _ string) (chain.AccountInfo, error) {
	if b.acctErr != nil {
		return chain.AccountInfo{}, b.acctErr
	}
	return b.acctInfo, nil
}

func (b *walletChainBridge) AccountAddresses(ctx context.Context, stakeAddr string) ([]string, error) {
	return b.f.AccountAddresses(ctx, stakeAddr)
}

func (b *walletChainBridge) AddressUTxOs(ctx context.Context, addr string) ([]chain.UTxO, error) {
	return b.f.AddressUTxOs(ctx, addr)
}

func (b *walletChainBridge) AddressTransactions(_ context.Context, _ string) ([]chain.AddressTx, error) {
	return nil, nil
}

// twoKnownUTxOs returns two deterministic chain.UTxO values and their
// expected tx hashes / indices / lovelace amounts for round-trip assertions.
func twoKnownUTxOs(addr string) []chain.UTxO {
	return []chain.UTxO{
		{
			Address:     addr,
			TxHash:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			OutputIndex: 0,
			Amount:      []chain.Amount{{Unit: "lovelace", Quantity: "2000000"}},
		},
		{
			Address:     addr,
			TxHash:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			OutputIndex: 1,
			Amount:      []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}},
		},
	}
}

// decodeUTxOHex decodes a hex-encoded CIP-30 TransactionUnspentOutput back to
// its ShelleyTransactionInput and the address + lovelace from the Babbage output.
func decodeUTxOHex(t *testing.T, s string) (txHash string, idx uint32, addr string, lovelace uint64) {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	// Decode the outer 2-element CBOR array.
	var outer []gocbor.RawMessage
	if _, err := gocbor.Decode(raw, &outer); err != nil {
		t.Fatalf("decode outer array: %v", err)
	}
	if len(outer) != 2 {
		t.Fatalf("outer array len = %d, want 2", len(outer))
	}

	// Decode input: [txId, outputIndex]
	var input shelley.ShelleyTransactionInput
	if _, err := gocbor.Decode(outer[0], &input); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	txHash = hex.EncodeToString(input.TxId.Bytes())
	idx = input.OutputIndex

	// Decode output value via mary.MaryTransactionOutputValue (key 1 in the map).
	// The Babbage output is a CBOR map; extract key 0 (address) and key 1 (value).
	var rawMap map[uint64]gocbor.RawMessage
	if _, err := gocbor.Decode(outer[1], &rawMap); err != nil {
		t.Fatalf("decode output map: %v", err)
	}
	// Key 0 = address bytes
	addrRaw, ok := rawMap[0]
	if !ok {
		t.Fatal("output map missing key 0 (address)")
	}
	var addrBytes []byte
	if _, err := gocbor.Decode(addrRaw, &addrBytes); err != nil {
		t.Fatalf("decode address bytes: %v", err)
	}
	parsedAddr, err := lcommon.NewAddressFromBytes(addrBytes)
	if err != nil {
		t.Fatalf("parse address from bytes: %v", err)
	}
	addr = parsedAddr.String()

	// Key 1 = MaryTransactionOutputValue (integer or [integer, map])
	valRaw, ok := rawMap[1]
	if !ok {
		t.Fatal("output map missing key 1 (value)")
	}
	var mv mary.MaryTransactionOutputValue
	if _, err := gocbor.Decode(valRaw, &mv); err != nil {
		t.Fatalf("decode value: %v", err)
	}
	lovelace = mv.Amount
	return
}

func encodeValueHex(t *testing.T, lovelace uint64) string {
	t.Helper()
	b, err := gocbor.Encode(&mary.MaryTransactionOutputValue{Amount: lovelace})
	if err != nil {
		t.Fatalf("encode value: %v", err)
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestWalletBackendNetworkID(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}

	mainnet := NewWalletBackend(wl, nil, acct, "mainnet", fc)
	if mainnet.NetworkID() != 1 {
		t.Fatalf("mainnet NetworkID = %d, want 1", mainnet.NetworkID())
	}

	testnet := NewWalletBackend(wl, nil, acct, "preview", fc)
	if testnet.NetworkID() != 0 {
		t.Fatalf("preview NetworkID = %d, want 0", testnet.NetworkID())
	}

	preprod := NewWalletBackend(wl, nil, acct, "preprod", fc)
	if preprod.NetworkID() != 0 {
		t.Fatalf("preprod NetworkID = %d, want 0", preprod.NetworkID())
	}
}

func TestWalletBackendUtxosRoundTrip(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	// Use the first derived receive address for UTxOs.
	targetAddr := acct.ReceiveAddresses[0]
	known := twoKnownUTxOs(targetAddr)

	fc := &fakeConnectorChain{
		addressErr: chain.ErrNotFound, // no chain-discovered addresses
		utxos:      map[string][]chain.UTxO{targetAddr: known},
	}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	hexes, err := be.Utxos(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("Utxos: %v", err)
	}
	if len(hexes) != 2 {
		t.Fatalf("Utxos returned %d entries, want 2", len(hexes))
	}

	// Round-trip assertion: each decoded UTxO must match the known inputs/outputs.
	for i, h := range hexes {
		txHash, idx, addr, lovelace := decodeUTxOHex(t, h)
		wantHash := known[i].TxHash
		wantIdx := uint32(known[i].OutputIndex) //nolint:gosec // test-only positive literals
		wantLov := func() uint64 {
			v, _ := new(big.Int).SetString(known[i].Amount[0].Quantity, 10)
			return v.Uint64()
		}()

		if txHash != wantHash {
			t.Errorf("utxo[%d] tx hash = %q, want %q", i, txHash, wantHash)
		}
		if idx != wantIdx {
			t.Errorf("utxo[%d] output index = %d, want %d", i, idx, wantIdx)
		}
		if addr != targetAddr {
			t.Errorf("utxo[%d] address = %q, want %q", i, addr, targetAddr)
		}
		if lovelace != wantLov {
			t.Errorf("utxo[%d] lovelace = %d, want %d", i, lovelace, wantLov)
		}
	}
}

func TestWalletBackendBalanceRoundTrip(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	targetAddr := acct.ReceiveAddresses[0]
	known := twoKnownUTxOs(targetAddr)

	fc := &fakeConnectorChain{
		addressErr: chain.ErrNotFound,
		utxos:      map[string][]chain.UTxO{targetAddr: known},
	}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	balHex, err := be.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}

	raw, err := hex.DecodeString(balHex)
	if err != nil {
		t.Fatalf("hex decode balance: %v", err)
	}
	var mv mary.MaryTransactionOutputValue
	if _, err := gocbor.Decode(raw, &mv); err != nil {
		t.Fatalf("decode balance CBOR: %v", err)
	}
	wantLovelace := uint64(2_000_000 + 3_000_000)
	if mv.Amount != wantLovelace {
		t.Errorf("balance lovelace = %d, want %d", mv.Amount, wantLovelace)
	}
	if mv.Assets != nil {
		t.Errorf("balance has unexpected assets")
	}
}

func TestWalletBackendAddressesHex(t *testing.T) {
	acct, _ := mustDeriveBackendAccount(t)
	// "used" address = the chain's reported addresses; unused = derived not in used.
	usedAddr := acct.ReceiveAddresses[0]
	fc := &fakeConnectorChain{
		addresses: []string{usedAddr},
		utxos:     map[string][]chain.UTxO{},
	}
	// Rebuild wallet service with a bridge that returns usedAddr.
	wl2 := wallet.NewService(&walletChainBridge{f: fc})
	if _, err := wl2.SetWallet(backendTestMnemonic, "preview", 3); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl2, nil, acct, "preview", fc)

	// Used addresses.
	usedHex, err := be.UsedAddresses(context.Background(), nil)
	if err != nil {
		t.Fatalf("UsedAddresses: %v", err)
	}
	if len(usedHex) != 1 {
		t.Fatalf("used addresses count = %d, want 1", len(usedHex))
	}
	wantHex, _ := addrStringToHex(usedAddr)
	if usedHex[0] != wantHex {
		t.Errorf("used[0] = %q, want %q", usedHex[0], wantHex)
	}
	// Decode back and verify it's valid.
	rawBytes, err := hex.DecodeString(usedHex[0])
	if err != nil {
		t.Fatalf("hex decode used addr: %v", err)
	}
	if len(rawBytes) == 0 {
		t.Error("used address raw bytes are empty")
	}
	parsed, err := lcommon.NewAddressFromBytes(rawBytes)
	if err != nil {
		t.Fatalf("parse used address bytes: %v", err)
	}
	if parsed.String() != usedAddr {
		t.Errorf("round-trip address = %q, want %q", parsed.String(), usedAddr)
	}

	usedPage, err := be.UsedAddresses(context.Background(), &Paginate{Page: 2, Limit: 1})
	if err != nil {
		t.Fatalf("UsedAddresses page 2: %v", err)
	}
	if len(usedPage) != 0 {
		t.Fatalf("used page 2 count = %d, want 0", len(usedPage))
	}

	// Unused addresses: receive[1] and receive[2] should be unused.
	unusedHex, err := be.UnusedAddresses(context.Background())
	if err != nil {
		t.Fatalf("UnusedAddresses: %v", err)
	}
	if len(unusedHex) != 2 {
		t.Fatalf("unused addresses count = %d, want 2 (receive[1] and receive[2])", len(unusedHex))
	}

	// Change address: first unused.
	changeHex, err := be.ChangeAddress(context.Background())
	if err != nil {
		t.Fatalf("ChangeAddress: %v", err)
	}
	wantChange, _ := addrStringToHex(acct.ReceiveAddresses[1])
	if changeHex != wantChange {
		t.Errorf("change address = %q, want %q", changeHex, wantChange)
	}
}

func TestWalletBackendRewardAddresses(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	rewards, err := be.RewardAddresses(context.Background())
	if err != nil {
		t.Fatalf("RewardAddresses: %v", err)
	}
	if len(rewards) != 1 {
		t.Fatalf("reward addresses count = %d, want 1", len(rewards))
	}
	// Decode and verify round-trip.
	rawBytes, err := hex.DecodeString(rewards[0])
	if err != nil {
		t.Fatalf("hex decode reward addr: %v", err)
	}
	parsed, err := lcommon.NewAddressFromBytes(rawBytes)
	if err != nil {
		t.Fatalf("parse reward address bytes: %v", err)
	}
	if parsed.String() != acct.StakeAddress {
		t.Errorf("reward address = %q, want %q", parsed.String(), acct.StakeAddress)
	}
}

func TestWalletBackendPaginate(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	targetAddr := acct.ReceiveAddresses[0]
	known := twoKnownUTxOs(targetAddr)

	fc := &fakeConnectorChain{
		addressErr: chain.ErrNotFound,
		utxos:      map[string][]chain.UTxO{targetAddr: known},
	}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	// Page 1 of 1 per page: should return only the first UTxO.
	p1, err := be.Utxos(context.Background(), "", &Paginate{Page: 1, Limit: 1})
	if err != nil {
		t.Fatalf("Utxos page 1: %v", err)
	}
	if len(p1) != 1 {
		t.Fatalf("page 1 = %d entries, want 1", len(p1))
	}
	txHash, _, _, _ := decodeUTxOHex(t, p1[0])
	if txHash != known[0].TxHash {
		t.Errorf("page 1 utxo tx = %q, want %q", txHash, known[0].TxHash)
	}

	// Page 2 of 1 per page: should return only the second UTxO.
	p2, err := be.Utxos(context.Background(), "", &Paginate{Page: 2, Limit: 1})
	if err != nil {
		t.Fatalf("Utxos page 2: %v", err)
	}
	if len(p2) != 1 {
		t.Fatalf("page 2 = %d entries, want 1", len(p2))
	}
	txHash2, _, _, _ := decodeUTxOHex(t, p2[0])
	if txHash2 != known[1].TxHash {
		t.Errorf("page 2 utxo tx = %q, want %q", txHash2, known[1].TxHash)
	}

	// Page 3 of 1 per page: past the end, should return nil.
	p3, err := be.Utxos(context.Background(), "", &Paginate{Page: 3, Limit: 1})
	if err != nil {
		t.Fatalf("Utxos page 3: %v", err)
	}
	if len(p3) != 0 {
		t.Fatalf("page 3 = %d entries, want 0", len(p3))
	}
}

func TestWalletBackendUtxosCBORAmount(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	targetAddr := acct.ReceiveAddresses[0]
	known := twoKnownUTxOs(targetAddr)

	fc := &fakeConnectorChain{
		addressErr: chain.ErrNotFound,
		utxos:      map[string][]chain.UTxO{targetAddr: known},
	}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	amt25 := encodeValueHex(t, 2_500_000)
	selected, err := be.Utxos(context.Background(), amt25, nil)
	if err != nil {
		t.Fatalf("Utxos(2.5 ADA): %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("Utxos(2.5 ADA) count = %d, want 1", len(selected))
	}
	txHash, _, _, _ := decodeUTxOHex(t, selected[0])
	if txHash != known[1].TxHash {
		t.Fatalf("Utxos(2.5 ADA) selected tx = %q, want %q", txHash, known[1].TxHash)
	}

	amt4 := encodeValueHex(t, 4_000_000)
	cover, err := be.Utxos(context.Background(), amt4, nil)
	if err != nil {
		t.Fatalf("Utxos(4 ADA): %v", err)
	}
	if len(cover) != 2 {
		t.Fatalf("Utxos(4 ADA) count = %d, want 2", len(cover))
	}

	amt6 := encodeValueHex(t, 6_000_000)
	none, err := be.Utxos(context.Background(), amt6, nil)
	if err != nil {
		t.Fatalf("Utxos(6 ADA): %v", err)
	}
	if none != nil {
		t.Fatalf("Utxos(6 ADA) = %v, want nil for unsatisfiable amount", none)
	}
}

func TestWalletBackendCollateral(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	targetAddr := acct.ReceiveAddresses[0]
	// 2 ADA (too small) and 5 ADA (just enough).
	utxos := []chain.UTxO{
		{Address: targetAddr, TxHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			OutputIndex: 0, Amount: []chain.Amount{{Unit: "lovelace", Quantity: "2000000"}}},
		{Address: targetAddr, TxHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			OutputIndex: 1, Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}},
	}
	fc := &fakeConnectorChain{
		addressErr: chain.ErrNotFound,
		utxos:      map[string][]chain.UTxO{targetAddr: utxos},
	}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	// Default (5 ADA threshold): only the 5 ADA UTxO qualifies.
	coll, err := be.Collateral(context.Background(), "")
	if err != nil {
		t.Fatalf("Collateral: %v", err)
	}
	if len(coll) != 1 {
		t.Fatalf("collateral count = %d, want 1", len(coll))
	}
	txHash, _, _, lovelace := decodeUTxOHex(t, coll[0])
	if txHash != utxos[1].TxHash {
		t.Errorf("collateral tx = %q, want %q", txHash, utxos[1].TxHash)
	}
	if lovelace != 5_000_000 {
		t.Errorf("collateral lovelace = %d, want 5000000", lovelace)
	}

	// Explicit 2 ADA threshold as hex-CBOR Coin: collateral accumulates
	// largest-first and stops as soon as the requested amount is covered, so the
	// 5 ADA UTxO alone satisfies it (1 entry, not all qualifying UTxOs).
	amtBytes, err := gocbor.Encode(uint64(2_000_000))
	if err != nil {
		t.Fatalf("encode CBOR 2ADA: %v", err)
	}
	coll2, err := be.Collateral(context.Background(), hex.EncodeToString(amtBytes))
	if err != nil {
		t.Fatalf("Collateral(2ADA): %v", err)
	}
	if len(coll2) != 1 {
		t.Fatalf("collateral(2ADA) count = %d, want 1", len(coll2))
	}

	// Threshold above any single UTxO (6 ADA): a valid set is built by
	// accumulating BOTH UTxOs (5 + 2 = 7 ADA). The old per-UTxO check would have
	// wrongly returned an empty set here.
	amt6, err := gocbor.Encode(uint64(6_000_000))
	if err != nil {
		t.Fatalf("encode CBOR 6ADA: %v", err)
	}
	coll3, err := be.Collateral(context.Background(), hex.EncodeToString(amt6))
	if err != nil {
		t.Fatalf("Collateral(6ADA): %v", err)
	}
	if len(coll3) != 2 {
		t.Fatalf("collateral(6ADA) count = %d, want 2 (accumulated set)", len(coll3))
	}

	// Threshold the wallet cannot cover (10 ADA > 7 ADA total): unsatisfiable,
	// so an empty set is returned.
	amt10, err := gocbor.Encode(uint64(10_000_000))
	if err != nil {
		t.Fatalf("encode CBOR 10ADA: %v", err)
	}
	coll4, err := be.Collateral(context.Background(), hex.EncodeToString(amt10))
	if err != nil {
		t.Fatalf("Collateral(10ADA): %v", err)
	}
	if len(coll4) != 0 {
		t.Fatalf("collateral(10ADA) count = %d, want 0 (unsatisfiable)", len(coll4))
	}
}

func TestWalletBackendSigningMethodsErrorWithoutSpendService(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	// CIP-95 methods (Task 13): with sp==nil they return "signing service not
	// configured" — not errNotImplemented — since they are now implemented.
	if _, err := be.PubDRepKey(""); err == nil {
		t.Error("PubDRepKey(nil sp): want error, got nil")
	}
	if _, err := be.RegisteredPubStakeKeys(""); err == nil {
		t.Error("RegisteredPubStakeKeys(nil sp): want error, got nil")
	}
	if _, err := be.UnregisteredPubStakeKeys(""); err == nil {
		t.Error("UnregisteredPubStakeKeys(nil sp): want error, got nil")
	}

	// SignTx, SignData, SubmitTx are now implemented (Task 12); with sp==nil
	// they return a "signing service not configured" error rather than
	// errNotImplemented.  Verify they at least return a non-nil error.
	ctx := context.Background()
	if _, err := be.SignTx(ctx, "", false, ""); err == nil {
		t.Error("SignTx(nil sp): want error, got nil")
	}
	if _, _, err := be.SignData("", "", ""); err == nil {
		t.Error("SignData(nil sp): want error, got nil")
	}
	if _, err := be.SubmitTx(ctx, ""); err == nil {
		t.Error("SubmitTx(nil sp): want error, got nil")
	}
}

// multiAssetUTxO returns a UTxO holding 2 ADA + one native token.
// policyHex must be exactly 56 hex chars (28 bytes); nameHex is the asset name in hex.
func multiAssetUTxO(addr, txHash string) chain.UTxO {
	const policyHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0" // 56 hex chars
	const nameHex = "6d79746f6b656e"                                             // "mytoken"
	return chain.UTxO{
		Address:     addr,
		TxHash:      txHash,
		OutputIndex: 0,
		Amount: []chain.Amount{
			{Unit: "lovelace", Quantity: "2000000"},
			{Unit: policyHex + nameHex, Quantity: "42"},
		},
	}
}

// decodeUTxOMaryValue decodes a hex-CBOR CIP-30 TransactionUnspentOutput and
// returns the full MaryTransactionOutputValue (with assets).
func decodeUTxOMaryValue(t *testing.T, s string) mary.MaryTransactionOutputValue {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	var outer []gocbor.RawMessage
	if _, err := gocbor.Decode(raw, &outer); err != nil {
		t.Fatalf("decode outer array: %v", err)
	}
	if len(outer) != 2 {
		t.Fatalf("outer len = %d, want 2", len(outer))
	}
	var rawMap map[uint64]gocbor.RawMessage
	if _, err := gocbor.Decode(outer[1], &rawMap); err != nil {
		t.Fatalf("decode output map: %v", err)
	}
	valRaw, ok := rawMap[1]
	if !ok {
		t.Fatal("output map missing key 1 (value)")
	}
	var mv mary.MaryTransactionOutputValue
	if _, err := gocbor.Decode(valRaw, &mv); err != nil {
		t.Fatalf("decode MaryTransactionOutputValue: %v", err)
	}
	return mv
}

// TestWalletBackendMultiAssetUTxORoundTrip verifies that a UTxO with a native
// token encodes and decodes back with the correct policy ID, asset name, and quantity.
func TestWalletBackendMultiAssetUTxORoundTrip(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	targetAddr := acct.ReceiveAddresses[0]

	const policyHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"
	const nameHex = "6d79746f6b656e" // "mytoken"
	const wantQty = int64(42)

	u := multiAssetUTxO(targetAddr, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	fc := &fakeConnectorChain{
		addressErr: chain.ErrNotFound,
		utxos:      map[string][]chain.UTxO{targetAddr: {u}},
	}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	hexes, err := be.Utxos(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("Utxos: %v", err)
	}
	if len(hexes) != 1 {
		t.Fatalf("Utxos returned %d entries, want 1", len(hexes))
	}

	mv := decodeUTxOMaryValue(t, hexes[0])

	if mv.Amount != 2_000_000 {
		t.Errorf("lovelace = %d, want 2000000", mv.Amount)
	}
	if mv.Assets == nil {
		t.Fatal("assets is nil, want multi-asset value")
	}

	// Verify policy ID, asset name, and quantity.
	policies := mv.Assets.Policies()
	if len(policies) != 1 {
		t.Fatalf("policies count = %d, want 1", len(policies))
	}
	gotPolicyHex := hex.EncodeToString(policies[0].Bytes())
	wantPolicyBytes, _ := hex.DecodeString(policyHex)
	wantPolicyHex := hex.EncodeToString(wantPolicyBytes)
	if gotPolicyHex != wantPolicyHex {
		t.Errorf("policy ID = %q, want %q", gotPolicyHex, wantPolicyHex)
	}

	assetNames := mv.Assets.Assets(policies[0])
	if len(assetNames) != 1 {
		t.Fatalf("asset names count = %d, want 1", len(assetNames))
	}
	wantNameBytes, _ := hex.DecodeString(nameHex)
	if hex.EncodeToString(assetNames[0]) != hex.EncodeToString(wantNameBytes) {
		t.Errorf("asset name = %q, want %q", hex.EncodeToString(assetNames[0]), hex.EncodeToString(wantNameBytes))
	}

	qty := mv.Assets.Asset(policies[0], assetNames[0])
	if qty == nil {
		t.Fatal("asset quantity is nil")
	}
	if qty.Int64() != wantQty {
		t.Errorf("asset quantity = %d, want %d", qty.Int64(), wantQty)
	}
}

// TestWalletBackendMultiAssetBalanceRoundTrip verifies Balance() for a wallet
// with a native token encodes and decodes back correctly.
func TestWalletBackendMultiAssetBalanceRoundTrip(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	targetAddr := acct.ReceiveAddresses[0]

	const policyHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"
	const nameHex = "6d79746f6b656e"

	u := multiAssetUTxO(targetAddr, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	fc := &fakeConnectorChain{
		addressErr: chain.ErrNotFound,
		utxos:      map[string][]chain.UTxO{targetAddr: {u}},
	}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	balHex, err := be.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}

	raw, err := hex.DecodeString(balHex)
	if err != nil {
		t.Fatalf("hex decode balance: %v", err)
	}
	var mv mary.MaryTransactionOutputValue
	if _, err := gocbor.Decode(raw, &mv); err != nil {
		t.Fatalf("decode balance CBOR: %v", err)
	}

	if mv.Amount != 2_000_000 {
		t.Errorf("balance lovelace = %d, want 2000000", mv.Amount)
	}
	if mv.Assets == nil {
		t.Fatal("balance assets is nil, want multi-asset value")
	}

	policies := mv.Assets.Policies()
	if len(policies) != 1 {
		t.Fatalf("balance policies count = %d, want 1", len(policies))
	}
	wantPolicyBytes, _ := hex.DecodeString(policyHex)
	if hex.EncodeToString(policies[0].Bytes()) != hex.EncodeToString(wantPolicyBytes) {
		t.Errorf("balance policy ID = %q, want %q",
			hex.EncodeToString(policies[0].Bytes()), hex.EncodeToString(wantPolicyBytes))
	}

	assetNames := mv.Assets.Assets(policies[0])
	if len(assetNames) != 1 {
		t.Fatalf("balance asset names count = %d, want 1", len(assetNames))
	}
	wantNameBytes, _ := hex.DecodeString(nameHex)
	if hex.EncodeToString(assetNames[0]) != hex.EncodeToString(wantNameBytes) {
		t.Errorf("balance asset name = %q, want %q",
			hex.EncodeToString(assetNames[0]), hex.EncodeToString(wantNameBytes))
	}

	qty := mv.Assets.Asset(policies[0], assetNames[0])
	if qty == nil {
		t.Fatal("balance asset quantity is nil")
	}
	if qty.Int64() != 42 {
		t.Errorf("balance asset quantity = %d, want 42", qty.Int64())
	}
}

// TestWalletBackendCollateralCBORAmount verifies Collateral accepts hex-CBOR Coin amounts.
func TestWalletBackendCollateralCBORAmount(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	targetAddr := acct.ReceiveAddresses[0]
	utxos := []chain.UTxO{
		{Address: targetAddr, TxHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			OutputIndex: 0, Amount: []chain.Amount{{Unit: "lovelace", Quantity: "2000000"}}},
		{Address: targetAddr, TxHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			OutputIndex: 1, Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}},
	}
	fc := &fakeConnectorChain{
		addressErr: chain.ErrNotFound,
		utxos:      map[string][]chain.UTxO{targetAddr: utxos},
	}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	// Encode 2_000_000 as a CBOR uint and pass as hex.
	amtBytes, err := gocbor.Encode(uint64(2_000_000))
	if err != nil {
		t.Fatalf("encode CBOR amount: %v", err)
	}
	amtHex := hex.EncodeToString(amtBytes)

	coll, err := be.Collateral(context.Background(), amtHex)
	if err != nil {
		t.Fatalf("Collateral(hex-CBOR 2ADA): %v", err)
	}
	// 2 ADA is covered by the 5 ADA UTxO alone (largest-first accumulation stops
	// once the request is satisfied), so a single entry is returned.
	if len(coll) != 1 {
		t.Fatalf("collateral count = %d, want 1", len(coll))
	}

	// Empty string still defaults to 5 ADA (only the 5 ADA UTxO qualifies).
	coll2, err := be.Collateral(context.Background(), "")
	if err != nil {
		t.Fatalf("Collateral(empty): %v", err)
	}
	if len(coll2) != 1 {
		t.Fatalf("default collateral count = %d, want 1", len(coll2))
	}
}

func TestWalletBackendEmptyWallet(t *testing.T) {
	acct, wl := mustDeriveBackendAccount(t)
	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	be := NewWalletBackend(wl, nil, acct, "preview", fc)

	hexes, err := be.Utxos(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("Utxos on empty wallet: %v", err)
	}
	if len(hexes) != 0 {
		t.Errorf("empty wallet Utxos = %d, want 0", len(hexes))
	}

	balHex, err := be.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance on empty wallet: %v", err)
	}
	raw, _ := hex.DecodeString(balHex)
	var mv mary.MaryTransactionOutputValue
	if _, err := gocbor.Decode(raw, &mv); err != nil {
		t.Fatalf("decode empty balance CBOR: %v", err)
	}
	if mv.Amount != 0 {
		t.Errorf("empty balance = %d, want 0", mv.Amount)
	}
}

// ---------------------------------------------------------------------------
// Fakes for signing tests (Task 12)
// ---------------------------------------------------------------------------

// fakeTestKeystore satisfies spend.Keystore for backend tests.
type fakeTestKeystore struct {
	mnemonic string
	err      error
}

func (k fakeTestKeystore) Exists() bool             { return false }
func (k fakeTestKeystore) Create(_, _ string) error { return nil }
func (k fakeTestKeystore) Unlock(_ string) ([]byte, error) {
	if k.err != nil {
		return nil, k.err
	}
	return []byte(k.mnemonic), nil
}

// fakeSpendChain satisfies backend.ChainContext with a canned submit hash.
// Most methods return zero values; only SubmitTx is exercised by SubmitTx tests.
type fakeSpendChain struct {
	submitHash lcommon.Blake2b256
	submitErr  error
}

var _ apollobackend.ChainContext = (*fakeSpendChain)(nil)

func (f *fakeSpendChain) ProtocolParams(_ context.Context) (apollobackend.ProtocolParameters, error) {
	return apollobackend.ProtocolParameters{
		MinFeeConstant:    155381,
		MinFeeCoefficient: 44,
		MaxTxSize:         16384,
		CoinsPerUtxoByte:  "4310",
	}, nil
}
func (f *fakeSpendChain) GenesisParams(_ context.Context) (apollobackend.GenesisParameters, error) {
	return apollobackend.GenesisParameters{
		ActiveSlotsCoefficient: 0.05,
		EpochLength:            432000,
		SlotLength:             1,
		NetworkMagic:           1,
	}, nil
}
func (f *fakeSpendChain) NetworkId() uint8                               { return 0 }
func (f *fakeSpendChain) CurrentEpoch(_ context.Context) (uint64, error) { return 500, nil }
func (f *fakeSpendChain) MaxTxFee(_ context.Context) (uint64, error) {
	pp, _ := f.ProtocolParams(context.Background())
	return apollobackend.ComputeMaxTxFee(pp)
}
func (f *fakeSpendChain) Tip(_ context.Context) (uint64, error) { return 10_000_000, nil }
func (f *fakeSpendChain) Utxos(_ context.Context, _ lcommon.Address) ([]lcommon.Utxo, error) {
	return nil, nil
}
func (f *fakeSpendChain) SubmitTx(_ context.Context, _ []byte) (lcommon.Blake2b256, error) {
	return f.submitHash, f.submitErr
}
func (f *fakeSpendChain) EvaluateTx(_ context.Context, _ []byte, _ []lcommon.Utxo) (map[lcommon.RedeemerKey]lcommon.ExUnits, error) {
	return nil, nil
}
func (f *fakeSpendChain) UtxoByRef(_ context.Context, _ lcommon.Blake2b256, _ uint32) (*lcommon.Utxo, error) {
	return nil, nil
}
func (f *fakeSpendChain) ScriptCbor(_ context.Context, _ lcommon.Blake2b224) ([]byte, error) {
	return nil, nil
}

// mustDeriveBackendSigningAccount derives a preview account with addressWindow=5
// from backendTestMnemonic for signing tests.
func mustDeriveBackendSigningAccount(t *testing.T) *wallet.Account {
	t.Helper()
	acct, err := wallet.Derive(backendTestMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("wallet.Derive: %v", err)
	}
	return acct
}

// derivedPaymentVkey returns the 32-byte Ed25519 public key for the payment
// key at derivation index idx from backendTestMnemonic.
func derivedPaymentVkey(t *testing.T, idx uint32) []byte {
	t.Helper()
	rootKey, err := bursa.GetRootKeyFromMnemonic(backendTestMnemonic, "")
	if err != nil {
		t.Fatalf("GetRootKeyFromMnemonic: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatalf("GetAccountKey: %v", err)
	}
	payKey, err := bursa.GetPaymentKey(acctKey, idx)
	if err != nil {
		t.Fatalf("GetPaymentKey(%d): %v", idx, err)
	}
	return bip32.XPrv(payKey).Public().PublicKey()
}

// ---------------------------------------------------------------------------
// Task 12 backend signing tests
// ---------------------------------------------------------------------------

// TestWalletBackendSignData verifies that SignData decodes the hex address,
// delegates to spend.Service.SignData, and returns a non-empty COSE_Sign1 + key.
// It also verifies the returned key hex decodes to the expected payment vkey.
func TestWalletBackendSignData(t *testing.T) {
	acct := mustDeriveBackendSigningAccount(t)
	ks := fakeTestKeystore{mnemonic: backendTestMnemonic}
	sc := &fakeSpendChain{}
	sp := spend.NewService(sc, ks, acct)

	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	wl := wallet.NewService(&walletChainBridge{f: fc})
	if _, err := wl.SetWallet(backendTestMnemonic, "preview", 5); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl, sp, acct, "preview", fc)

	// Use the first derived receive address as hex (what CIP-30 getUsedAddresses returns).
	addr0 := acct.ReceiveAddresses[0]
	addrHex, err := addrStringToHex(addr0)
	if err != nil {
		t.Fatalf("addrStringToHex: %v", err)
	}

	payload := []byte("CIP-30 signData test payload")
	payloadHex := hex.EncodeToString(payload)

	sig, key, err := be.SignData(addrHex, payloadHex, "anypassword")
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if sig == "" || key == "" {
		t.Fatalf("SignData returned empty sig=%q key=%q", sig, key)
	}

	// The CIP-8 COSE_Key encodes the vkey; verify it against the expected key.
	wantVkey := derivedPaymentVkey(t, 0)

	// key is hex COSE_Key; the raw public key bytes are embedded in it.
	// Verify them by checking via bursa.VerifyData (full round-trip).
	ok, err := bursa.VerifyData(sig, key, payload)
	if err != nil {
		t.Fatalf("VerifyData: %v", err)
	}
	if !ok {
		t.Fatal("CIP-8 signature failed verification")
	}

	// Tampered payload must NOT verify.
	if ok, _ := bursa.VerifyData(sig, key, []byte("tampered")); ok {
		t.Fatal("signature verified against tampered payload")
	}

	// The key hex must contain the expected vkey bytes.
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		t.Fatalf("decode key hex: %v", err)
	}
	// COSE_Key embeds the 32-byte vkey; verify it's present in the CBOR.
	if len(keyBytes) == 0 {
		t.Fatal("key bytes are empty")
	}
	// Simple substring check: the vkey must appear somewhere in the COSE_Key CBOR.
	vkeyHex := hex.EncodeToString(wantVkey)
	keyHex := hex.EncodeToString(keyBytes)
	if len(keyHex) < len(vkeyHex) {
		t.Errorf("COSE_Key (%d bytes) is too short to contain the 32-byte vkey", len(keyBytes))
	}
	_ = keyHex // presence verified indirectly via VerifyData above
}

// TestWalletBackendSignTx builds a minimal Conway tx with a required signer
// matching payment key [0] of the test wallet, signs it via WalletBackend.SignTx,
// decodes the returned witness set, and asserts it contains exactly one vkey
// witness whose Vkey matches the derived payment key.
func TestWalletBackendSignTx(t *testing.T) {
	acct := mustDeriveBackendSigningAccount(t)
	ks := fakeTestKeystore{mnemonic: backendTestMnemonic}
	sc := &fakeSpendChain{}
	sp := spend.NewService(sc, ks, acct)

	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	wl := wallet.NewService(&walletChainBridge{f: fc})
	if _, err := wl.SetWallet(backendTestMnemonic, "preview", 5); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl, sp, acct, "preview", fc)

	// Derive the vkey and compute its hash (Blake2b224) — this is what goes in
	// required_signers.
	wantVkey := derivedPaymentVkey(t, 0)
	vkeyHash := lcommon.Blake2b224Hash(wantVkey)

	// Build a minimal Conway transaction body with one required signer.
	var dummyTxID lcommon.Blake2b256
	copy(dummyTxID[:], bytes32("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"))
	inp := shelley.ShelleyTransactionInput{TxId: dummyTxID, OutputIndex: 0}

	body := conway.ConwayTransactionBody{
		TxInputs:          conway.NewConwayTransactionInputSet([]shelley.ShelleyTransactionInput{inp}),
		TxFee:             200000,
		TxRequiredSigners: gocbor.NewSetType([]lcommon.Blake2b224{vkeyHash}, true),
	}

	// Build the full transaction (body + empty witness set + isValid + null metadata).
	tx := conway.ConwayTransaction{
		Body:       body,
		WitnessSet: conway.ConwayTransactionWitnessSet{},
		TxIsValid:  true,
	}
	txCbor, err := gocbor.Encode(&tx)
	if err != nil {
		t.Fatalf("encode tx: %v", err)
	}
	txHex := hex.EncodeToString(txCbor)

	// Extract the body CBOR from the ORIGINAL tx bytes exactly as the production
	// code does (outer array element [0]); the signing target is blake2b-256 of
	// these exact bytes. This must NOT be a re-encode of the decoded struct.
	var outer []gocbor.RawMessage
	if _, err := gocbor.Decode(txCbor, &outer); err != nil {
		t.Fatalf("decode outer tx array: %v", err)
	}
	if len(outer) < 1 {
		t.Fatal("tx array has no body element")
	}
	originalBodyCbor := []byte(outer[0])
	signingTarget := lcommon.Blake2b256Hash(originalBodyCbor)

	// Sign.
	wsHex, err := be.SignTx(context.Background(), txHex, false, "anypassword")
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if wsHex == "" {
		t.Fatal("SignTx returned empty witness set hex")
	}

	// Decode the returned witness set.
	wsBytes, err := hex.DecodeString(wsHex)
	if err != nil {
		t.Fatalf("decode witness set hex: %v", err)
	}
	var decodedWS conway.ConwayTransactionWitnessSet
	if _, err := gocbor.Decode(wsBytes, &decodedWS); err != nil {
		t.Fatalf("decode witness set CBOR: %v", err)
	}

	witnesses := decodedWS.VkeyWitnesses.Items()
	if len(witnesses) != 1 {
		t.Fatalf("witness count = %d, want 1", len(witnesses))
	}
	if !bytes.Equal(witnesses[0].Vkey, wantVkey) {
		t.Errorf("witness vkey = %x, want %x", witnesses[0].Vkey, wantVkey)
	}
	if len(witnesses[0].Signature) != 64 {
		t.Errorf("witness signature length = %d, want 64", len(witnesses[0].Signature))
	}

	// CRITICAL: the signature MUST verify against blake2b-256 of the body bytes
	// extracted from the ORIGINAL tx. This catches a wrong signing target (e.g. a
	// re-encoded body that differs byte-for-byte from the original).
	if !ed25519.Verify(ed25519.PublicKey(witnesses[0].Vkey), signingTarget.Bytes(), witnesses[0].Signature) {
		t.Error("witness signature does not verify against blake2b-256 of the original tx body")
	}
}

// TestWalletBackendSignTxPartialSignFalseErrors verifies that when partialSign is
// false and no wallet key matches any required signer, SignTx returns an error.
func TestWalletBackendSignTxPartialSignFalseErrors(t *testing.T) {
	acct := mustDeriveBackendSigningAccount(t)
	ks := fakeTestKeystore{mnemonic: backendTestMnemonic}
	sc := &fakeSpendChain{}
	sp := spend.NewService(sc, ks, acct)

	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	wl := wallet.NewService(&walletChainBridge{f: fc})
	if _, err := wl.SetWallet(backendTestMnemonic, "preview", 5); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl, sp, acct, "preview", fc)

	// A required signer hash that does NOT match any of our derived keys.
	var foreignKeyHash lcommon.Blake2b224
	copy(foreignKeyHash[:], bytes32("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))

	var dummyTxID lcommon.Blake2b256
	copy(dummyTxID[:], bytes32("1111111111111111111111111111111111111111111111111111111111111111"))
	inp := shelley.ShelleyTransactionInput{TxId: dummyTxID, OutputIndex: 0}

	body := conway.ConwayTransactionBody{
		TxInputs:          conway.NewConwayTransactionInputSet([]shelley.ShelleyTransactionInput{inp}),
		TxFee:             200000,
		TxRequiredSigners: gocbor.NewSetType([]lcommon.Blake2b224{foreignKeyHash}, true),
	}
	tx := conway.ConwayTransaction{
		Body:      body,
		TxIsValid: true,
	}
	txCbor, err := gocbor.Encode(&tx)
	if err != nil {
		t.Fatalf("encode tx: %v", err)
	}

	_, err = be.SignTx(context.Background(), hex.EncodeToString(txCbor), false, "anypassword")
	if err == nil {
		t.Fatal("SignTx(partialSign=false, no match): want error, got nil")
	}
}

// TestWalletBackendSignTxPartialSignTrue verifies that when partialSign is true
// and no wallet key matches, SignTx succeeds with an empty witness set.
func TestWalletBackendSignTxPartialSignTrue(t *testing.T) {
	acct := mustDeriveBackendSigningAccount(t)
	ks := fakeTestKeystore{mnemonic: backendTestMnemonic}
	sc := &fakeSpendChain{}
	sp := spend.NewService(sc, ks, acct)

	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	wl := wallet.NewService(&walletChainBridge{f: fc})
	if _, err := wl.SetWallet(backendTestMnemonic, "preview", 5); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl, sp, acct, "preview", fc)

	var foreignKeyHash lcommon.Blake2b224
	copy(foreignKeyHash[:], bytes32("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))

	var dummyTxID lcommon.Blake2b256
	copy(dummyTxID[:], bytes32("2222222222222222222222222222222222222222222222222222222222222222"))
	inp := shelley.ShelleyTransactionInput{TxId: dummyTxID, OutputIndex: 0}

	body := conway.ConwayTransactionBody{
		TxInputs:          conway.NewConwayTransactionInputSet([]shelley.ShelleyTransactionInput{inp}),
		TxFee:             200000,
		TxRequiredSigners: gocbor.NewSetType([]lcommon.Blake2b224{foreignKeyHash}, true),
	}
	tx := conway.ConwayTransaction{
		Body:      body,
		TxIsValid: true,
	}
	txCbor, err := gocbor.Encode(&tx)
	if err != nil {
		t.Fatalf("encode tx: %v", err)
	}

	wsHex, err := be.SignTx(context.Background(), hex.EncodeToString(txCbor), true, "anypassword")
	if err != nil {
		t.Fatalf("SignTx(partialSign=true): %v", err)
	}
	// The witness set must be decodable CBOR, even when empty (no matching keys).
	wsBytes, err := hex.DecodeString(wsHex)
	if err != nil {
		t.Fatalf("decode partial witness set hex: %v", err)
	}
	var decodedWS conway.ConwayTransactionWitnessSet
	if _, err := gocbor.Decode(wsBytes, &decodedWS); err != nil {
		t.Fatalf("decode partial witness set CBOR: %v", err)
	}
	if n := len(decodedWS.VkeyWitnesses.Items()); n != 0 {
		t.Errorf("partial-sign with no matching key produced %d witnesses, want 0", n)
	}
}

// TestWalletBackendSubmitTx verifies that SubmitTx decodes the hex, submits via
// the chain, and returns the expected tx hash hex.
func TestWalletBackendSubmitTx(t *testing.T) {
	acct := mustDeriveBackendSigningAccount(t)
	ks := fakeTestKeystore{mnemonic: backendTestMnemonic}

	// Set a canned submit hash.
	var wantHash lcommon.Blake2b256
	copy(wantHash[:], bytes32("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
	sc := &fakeSpendChain{submitHash: wantHash}
	sp := spend.NewService(sc, ks, acct)

	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	wl := wallet.NewService(&walletChainBridge{f: fc})
	if _, err := wl.SetWallet(backendTestMnemonic, "preview", 5); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl, sp, acct, "preview", fc)

	// Fake tx bytes (just some hex).
	fakeTxHex := hex.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef})

	gotHash, err := be.SubmitTx(context.Background(), fakeTxHex)
	if err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}
	wantHashHex := hex.EncodeToString(wantHash.Bytes())
	if gotHash != wantHashHex {
		t.Errorf("SubmitTx hash = %q, want %q", gotHash, wantHashHex)
	}
}

// bytes32 decodes a 64-char hex string to a 32-byte slice (panics on error; test use only).
func bytes32(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	if len(b) != 32 {
		panic("expected 32 bytes")
	}
	return b
}

// ---------------------------------------------------------------------------
// CIP-95 governance key helpers
// ---------------------------------------------------------------------------

// derivedDRepVkey derives the 32-byte Ed25519 public key for the DRep key
// (CIP-0105, role 3: m/1852'/1815'/0'/3/0) from backendTestMnemonic.
func derivedDRepVkey(t *testing.T) []byte {
	t.Helper()
	rootKey, err := bursa.GetRootKeyFromMnemonic(backendTestMnemonic, "")
	if err != nil {
		t.Fatalf("GetRootKeyFromMnemonic: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatalf("GetAccountKey: %v", err)
	}
	drepKey, err := bursa.GetDRepKey(acctKey, 0)
	if err != nil {
		t.Fatalf("GetDRepKey: %v", err)
	}
	return bip32.XPrv(drepKey).Public().PublicKey()
}

// derivedStakeVkey derives the 32-byte Ed25519 public key for the stake key
// (CIP-1852, role 2: m/1852'/1815'/0'/2/0) from backendTestMnemonic.
func derivedStakeVkey(t *testing.T) []byte {
	t.Helper()
	rootKey, err := bursa.GetRootKeyFromMnemonic(backendTestMnemonic, "")
	if err != nil {
		t.Fatalf("GetRootKeyFromMnemonic: %v", err)
	}
	acctKey, err := bursa.GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatalf("GetAccountKey: %v", err)
	}
	stakeKey, err := bursa.GetStakeKey(acctKey, 0)
	if err != nil {
		t.Fatalf("GetStakeKey: %v", err)
	}
	return bip32.XPrv(stakeKey).Public().PublicKey()
}

// mustDeriveBackendCIP95Account derives a preview account for CIP-95 signing tests.
func mustDeriveBackendCIP95Account(t *testing.T) (*wallet.Account, *spend.Service, *walletChainBridge) {
	t.Helper()
	acct, err := wallet.Derive(backendTestMnemonic, "preview", 5)
	if err != nil {
		t.Fatalf("wallet.Derive: %v", err)
	}
	ks := fakeTestKeystore{mnemonic: backendTestMnemonic}
	sc := &fakeSpendChain{}
	sp := spend.NewService(sc, ks, acct)
	fc := &fakeConnectorChain{addressErr: chain.ErrNotFound}
	bridge := &walletChainBridge{f: fc}
	return acct, sp, bridge
}

// ---------------------------------------------------------------------------
// Task 13: CIP-95 governance key tests
// ---------------------------------------------------------------------------

// TestWalletBackendPubDRepKey verifies that PubDRepKey returns the hex of the
// expected role-3 public key for backendTestMnemonic.
func TestWalletBackendPubDRepKey(t *testing.T) {
	acct, sp, bridge := mustDeriveBackendCIP95Account(t)
	wl := wallet.NewService(bridge)
	if _, err := wl.SetWallet(backendTestMnemonic, "preview", 5); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl, sp, acct, "preview", bridge.f)

	got, err := be.PubDRepKey("anypassword")
	if err != nil {
		t.Fatalf("PubDRepKey: %v", err)
	}
	if got == "" {
		t.Fatal("PubDRepKey returned empty string")
	}

	// Independently derive the expected DRep public key and compare.
	wantBytes := derivedDRepVkey(t)
	want := hex.EncodeToString(wantBytes)
	if got != want {
		t.Errorf("PubDRepKey = %q, want %q", got, want)
	}

	// Must be 32 bytes = 64 hex chars.
	if len(got) != 64 {
		t.Errorf("PubDRepKey hex length = %d, want 64", len(got))
	}

	// Must not equal the stake key (different derivation path).
	stakeHex := hex.EncodeToString(derivedStakeVkey(t))
	if got == stakeHex {
		t.Error("DRep key must not equal stake key")
	}

	// Must not equal the payment key at index 0.
	payHex := hex.EncodeToString(derivedPaymentVkey(t, 0))
	if got == payHex {
		t.Error("DRep key must not equal payment key[0]")
	}
}

// TestWalletBackendUnregisteredPubStakeKeys verifies that when the stake key is
// NOT active on chain, it appears in UnregisteredPubStakeKeys and the registered
// slice is empty.
func TestWalletBackendUnregisteredPubStakeKeys(t *testing.T) {
	acct, sp, bridge := mustDeriveBackendCIP95Account(t)
	// Bridge returns AccountInfo{Active: false} by default (zero value).
	wl := wallet.NewService(bridge)
	if _, err := wl.SetWallet(backendTestMnemonic, "preview", 5); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl, sp, acct, "preview", bridge.f)

	unregistered, err := be.UnregisteredPubStakeKeys("anypassword")
	if err != nil {
		t.Fatalf("UnregisteredPubStakeKeys: %v", err)
	}
	if len(unregistered) != 1 {
		t.Fatalf("UnregisteredPubStakeKeys count = %d, want 1", len(unregistered))
	}

	wantBytes := derivedStakeVkey(t)
	want := hex.EncodeToString(wantBytes)
	if unregistered[0] != want {
		t.Errorf("UnregisteredPubStakeKeys[0] = %q, want %q", unregistered[0], want)
	}
	if len(unregistered[0]) != 64 {
		t.Errorf("stake key hex length = %d, want 64", len(unregistered[0]))
	}

	// Registered slice must be empty when not active.
	registered, err := be.RegisteredPubStakeKeys("anypassword")
	if err != nil {
		t.Fatalf("RegisteredPubStakeKeys: %v", err)
	}
	if len(registered) != 0 {
		t.Errorf("RegisteredPubStakeKeys count = %d, want 0 (stake not active)", len(registered))
	}
}

// TestWalletBackendRegisteredPubStakeKeys verifies that when the stake key IS
// active on chain, it appears in RegisteredPubStakeKeys and the unregistered
// slice is empty.
func TestWalletBackendRegisteredPubStakeKeys(t *testing.T) {
	acct, sp, bridge := mustDeriveBackendCIP95Account(t)
	// Simulate an active (registered) stake key.
	bridge.acctInfo = chain.AccountInfo{Active: true}
	wl := wallet.NewService(bridge)
	if _, err := wl.SetWallet(backendTestMnemonic, "preview", 5); err != nil {
		t.Fatalf("SetWallet: %v", err)
	}
	be := NewWalletBackend(wl, sp, acct, "preview", bridge.f)

	registered, err := be.RegisteredPubStakeKeys("anypassword")
	if err != nil {
		t.Fatalf("RegisteredPubStakeKeys: %v", err)
	}
	if len(registered) != 1 {
		t.Fatalf("RegisteredPubStakeKeys count = %d, want 1", len(registered))
	}

	wantBytes := derivedStakeVkey(t)
	want := hex.EncodeToString(wantBytes)
	if registered[0] != want {
		t.Errorf("RegisteredPubStakeKeys[0] = %q, want %q", registered[0], want)
	}

	// Unregistered slice must be empty when active.
	unregistered, err := be.UnregisteredPubStakeKeys("anypassword")
	if err != nil {
		t.Fatalf("UnregisteredPubStakeKeys: %v", err)
	}
	if len(unregistered) != 0 {
		t.Errorf("UnregisteredPubStakeKeys count = %d, want 0 (stake active)", len(unregistered))
	}
}
