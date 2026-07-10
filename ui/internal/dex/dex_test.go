package dex

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"
	shaicommon "github.com/blinklabs-io/shai/common"
	shaidex "github.com/blinklabs-io/shai/dex"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// A 28-byte token policy used across fixtures.
var tokenPolicy = mustHex("11223344556677889900aabbccddeeff00112233445566778899aabb")

// minswapV1Addr is the real mainnet script address shai locates Minswap V1 pools
// at — used so the scan actually maps a UTxO to the v1 parser.
const minswapV1Addr = "addr1z8snz7c4974vzdpxu65ruphl3zjdvtxw8strf2c2tmqnxzfgf2ypu62xjxel6aqdmr333p0ds377t4phv8098c8s8fmqffc3l3"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// minswapV1Datum builds a Minswap V1 pool datum for ADA/<token>.
func minswapV1Datum() []byte {
	assetA := cbor.NewConstructorEncoder(0, cbor.IndefLengthList{
		[]byte{}, // ADA: empty policy + empty name
		[]byte{},
	})
	assetB := cbor.NewConstructorEncoder(0, cbor.IndefLengthList{
		tokenPolicy,
		[]byte("TEST"),
	})
	feeSharingNone := cbor.NewConstructorEncoder(1, cbor.IndefLengthList{})
	datum := cbor.NewConstructorEncoder(0, cbor.IndefLengthList{
		assetA,
		assetB,
		uint64(1000000000), // totalLiquidity
		uint64(12345678),   // rootKLast
		feeSharingNone,
	})
	out, err := cbor.Encode(&datum)
	if err != nil {
		panic(err)
	}
	return out
}

// tokenUnit is the concatenated policy+name unit for the fixture token.
func tokenUnit() string {
	return hex.EncodeToString(tokenPolicy) + hex.EncodeToString([]byte("TEST"))
}

// fakeChain is a chainQuerier backed by in-memory fixtures. The call counters
// are mutex-protected so tests can drive it from concurrent goroutines (e.g.
// to prove scans are singleflight-coalesced) under -race.
type fakeChain struct {
	utxosByAddr map[string][]chain.UTxO
	outsByTx    map[string][]chain.TxOutput
	// txOutputsErr, keyed by tx hash, lets a test simulate a transport
	// failure (as opposed to chain.ErrNotFound) from the tx-utxos endpoint.
	txOutputsErr map[string]error

	mu        sync.Mutex
	txCalls   int
	addrCalls int
}

func (f *fakeChain) AddressUTxOs(_ context.Context, addr string) ([]chain.UTxO, error) {
	f.mu.Lock()
	f.addrCalls++
	f.mu.Unlock()
	us, ok := f.utxosByAddr[addr]
	if !ok {
		return nil, chain.ErrNotFound
	}
	return us, nil
}

func (f *fakeChain) TxOutputs(_ context.Context, txHash string) ([]chain.TxOutput, error) {
	f.mu.Lock()
	f.txCalls++
	f.mu.Unlock()
	if err, ok := f.txOutputsErr[txHash]; ok {
		return nil, err
	}
	outs, ok := f.outsByTx[txHash]
	if !ok {
		return nil, chain.ErrNotFound
	}
	return outs, nil
}

func (f *fakeChain) addressCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addrCalls
}

// --- value-CBOR build + parse round-trip ---

// TestEncodeTxOutRoundTripsThroughParser proves that the value CBOR we build
// from the node's flat amount list is exactly what a shai txOut-based parser
// (Minswap V1) reads back: the reserves come out matching the amounts in.
func TestEncodeTxOutRoundTripsThroughParser(t *testing.T) {
	amounts := []chain.Amount{
		{Unit: "lovelace", Quantity: "100000000"}, // 100 ADA
		{Unit: tokenUnit(), Quantity: "200000000"},
	}
	value, err := encodeValue(valueTxOut, amounts)
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}

	parser := shaidex.NewMinswapV1Parser()
	st, err := parser.ParsePoolDatum(minswapV1Datum(), value, "abc", 0, 0, time.Time{})
	if err != nil {
		t.Fatalf("ParsePoolDatum: %v", err)
	}
	if st.AssetX.Amount != 100000000 {
		t.Errorf("reserve X = %d, want 100000000", st.AssetX.Amount)
	}
	if st.AssetY.Amount != 200000000 {
		t.Errorf("reserve Y = %d, want 200000000", st.AssetY.Amount)
	}
}

func TestEncodeAssetMapShape(t *testing.T) {
	amounts := []chain.Amount{
		{Unit: "lovelace", Quantity: "1000000"},
		{Unit: tokenUnit(), Quantity: "5"},
	}
	b, err := encodeValue(valueAssetMap, amounts)
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	var decoded map[string]uint64
	if _, err := cbor.Decode(b, &decoded); err != nil {
		t.Fatalf("decode asset map: %v", err)
	}
	if decoded["lovelace"] != 1000000 {
		t.Errorf("lovelace = %d, want 1000000", decoded["lovelace"])
	}
	if decoded[tokenUnit()] != 5 {
		t.Errorf("token = %d, want 5", decoded[tokenUnit()])
	}
}

// --- Pools: scan + parse from the node, inline datum recovered via tx-utxos ---

func newServiceWithPool(t *testing.T, lovelace, token uint64) (*Service, *fakeChain) {
	t.Helper()
	datumHex := hex.EncodeToString(minswapV1Datum())
	fc := &fakeChain{
		utxosByAddr: map[string][]chain.UTxO{
			minswapV1Addr: {{
				Address:     minswapV1Addr,
				TxHash:      "pooltx",
				OutputIndex: 0,
				Amount: []chain.Amount{
					{Unit: "lovelace", Quantity: strconv.FormatUint(lovelace, 10)},
					{Unit: tokenUnit(), Quantity: strconv.FormatUint(token, 10)},
				},
				// address-utxos does not carry the inline datum (matches dingo).
				InlineDatum: nil,
			}},
		},
		outsByTx: map[string][]chain.TxOutput{
			"pooltx": {{
				Address:     minswapV1Addr,
				OutputIndex: 0,
				InlineDatum: &datumHex,
			}},
		},
	}
	return NewService(fc, "mainnet"), fc
}

func TestPoolsParsesNodeUTxO(t *testing.T) {
	svc, fc := newServiceWithPool(t, 100000000, 200000000)
	pools, err := svc.Pools(context.Background())
	if err != nil {
		t.Fatalf("Pools: %v", err)
	}
	if len(pools) != 1 {
		t.Fatalf("got %d pools, want 1", len(pools))
	}
	p := pools[0]
	if p.Protocol != "minswap-v1" {
		t.Errorf("protocol = %q, want minswap-v1", p.Protocol)
	}
	if p.AssetX != "lovelace" {
		t.Errorf("assetX = %q, want lovelace", p.AssetX)
	}
	if p.AssetY != tokenUnit() {
		t.Errorf("assetY = %q, want %q", p.AssetY, tokenUnit())
	}
	if p.ReserveX != "100000000" || p.ReserveY != "200000000" {
		t.Errorf("reserves = %s/%s, want 100000000/200000000", p.ReserveX, p.ReserveY)
	}
	if p.PriceXY != 2.0 {
		t.Errorf("priceXY = %f, want 2.0", p.PriceXY)
	}
	// inline datum had to be recovered from tx-utxos (one call).
	if fc.txCalls == 0 {
		t.Error("expected a tx-utxos call to recover the inline datum")
	}
}

func TestPoolsCachesScan(t *testing.T) {
	svc, fc := newServiceWithPool(t, 100000000, 200000000)
	if _, err := svc.Pools(context.Background()); err != nil {
		t.Fatalf("Pools #1: %v", err)
	}
	first := fc.txCalls
	if _, err := svc.Pools(context.Background()); err != nil {
		t.Fatalf("Pools #2: %v", err)
	}
	if fc.txCalls != first {
		t.Errorf("second Pools call re-scanned the node (txCalls %d → %d); expected cache hit", first, fc.txCalls)
	}
}

// TestPoolsCoalescesConcurrentScans proves that many concurrent callers
// hitting an unpopulated (or expired) cache trigger exactly one node scan,
// not one per caller: poolStates shares a single in-flight scan via
// singleflight.
func TestPoolsCoalescesConcurrentScans(t *testing.T) {
	// Baseline: how many pool addresses does a single scan query, over an
	// independent instance of the same fixtures.
	baseline, baselineFc := newServiceWithPool(t, 100000000, 200000000)
	if _, err := baseline.Pools(context.Background()); err != nil {
		t.Fatalf("Pools (baseline): %v", err)
	}
	wantCalls := baselineFc.addressCalls()

	svc, fc := newServiceWithPool(t, 100000000, 200000000)

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.Pools(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Pools()[%d]: %v", i, err)
		}
	}
	if got := fc.addressCalls(); got != wantCalls {
		t.Errorf("AddressUTxOs called %d times across %d concurrent cache-miss requests; want %d (one coalesced scan)",
			got, n, wantCalls)
	}
}

// TestPoolsSkipsUTxOWhenTxGenuinelyNotFound proves the pre-existing behavior
// is preserved: when the tx-utxos lookup for a pool UTxO's transaction reports
// chain.ErrNotFound (no such tx), that UTxO is silently skipped rather than
// failing the whole scan.
func TestPoolsSkipsUTxOWhenTxGenuinelyNotFound(t *testing.T) {
	fc := &fakeChain{
		utxosByAddr: map[string][]chain.UTxO{
			minswapV1Addr: {{
				Address:     minswapV1Addr,
				TxHash:      "goneTx",
				OutputIndex: 0,
				Amount: []chain.Amount{
					{Unit: "lovelace", Quantity: "100000000"},
				},
				InlineDatum: nil,
			}},
		},
		// outsByTx has no entry for "goneTx", so TxOutputs returns chain.ErrNotFound.
		outsByTx: map[string][]chain.TxOutput{},
	}
	svc := NewService(fc, "mainnet")

	pools, err := svc.Pools(context.Background())
	if err != nil {
		t.Fatalf("Pools: %v", err)
	}
	if len(pools) != 0 {
		t.Fatalf("got %d pools, want 0 (stray utxo should be skipped)", len(pools))
	}
}

// TestPoolsPropagatesTxOutputsTransportError proves the fix for a silent
// data-loss bug: a tx-utxos transport failure (as opposed to a genuine
// chain.ErrNotFound) must fail the request, not be swallowed as "not a pool".
// Silently dropping the pool would let Pools/Quote return an incomplete (or
// wrong) result while looking like a success.
func TestPoolsPropagatesTxOutputsTransportError(t *testing.T) {
	boom := errors.New("connection reset by peer")
	fc := &fakeChain{
		utxosByAddr: map[string][]chain.UTxO{
			minswapV1Addr: {{
				Address:     minswapV1Addr,
				TxHash:      "pooltx",
				OutputIndex: 0,
				Amount: []chain.Amount{
					{Unit: "lovelace", Quantity: "100000000"},
				},
				InlineDatum: nil,
			}},
		},
		txOutputsErr: map[string]error{"pooltx": boom},
	}
	svc := NewService(fc, "mainnet")

	_, err := svc.Pools(context.Background())
	if err == nil {
		t.Fatal("Pools: expected a transport-failure error, got nil (pool silently dropped)")
	}
	if !errors.Is(err, boom) {
		t.Errorf("Pools error = %v, want it to wrap %v", err, boom)
	}

	_, err = svc.Quote(context.Background(), "lovelace", tokenUnit(), 1000000)
	if err == nil {
		t.Fatal("Quote: expected a transport-failure error, got nil (pool silently dropped)")
	}
	if !errors.Is(err, boom) {
		t.Errorf("Quote error = %v, want it to wrap %v", err, boom)
	}
}

// --- Quote ---

func TestQuoteAdaToToken(t *testing.T) {
	svc, _ := newServiceWithPool(t, 100000000, 200000000)
	q, err := svc.Quote(context.Background(), "lovelace", tokenUnit(), 1000000)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if q.Protocol != "minswap-v1" {
		t.Errorf("protocol = %q, want minswap-v1", q.Protocol)
	}
	if q.AmountOut == "" || q.AmountOut == "0" {
		t.Errorf("amount_out = %q, want > 0", q.AmountOut)
	}
	out, _ := strconv.ParseUint(q.AmountOut, 10, 64)
	// 1 ADA in against a 100/200 pool with 0.3% fee yields a bit under 2 token.
	if out == 0 || out >= 2000000 {
		t.Errorf("amount_out = %d, want 0 < out < 2000000", out)
	}
	if q.EffectiveFee <= 0 || q.EffectiveFee >= 1 {
		t.Errorf("effective_fee = %f, want 0 < fee < 1", q.EffectiveFee)
	}
	if q.PriceImpactPct <= 0 {
		t.Errorf("price_impact_pct = %f, want > 0", q.PriceImpactPct)
	}
}

func TestQuoteUnknownPairNoRoute(t *testing.T) {
	svc, _ := newServiceWithPool(t, 100000000, 200000000)
	other := hex.EncodeToString(make([]byte, 28)) + hex.EncodeToString([]byte("NOPE"))
	_, err := svc.Quote(context.Background(), "lovelace", other, 1000000)
	if !errors.Is(err, ErrNoRoute) {
		t.Errorf("err = %v, want ErrNoRoute", err)
	}
}

func TestQuoteInvalidRequests(t *testing.T) {
	svc, _ := newServiceWithPool(t, 100000000, 200000000)
	cases := []struct {
		name    string
		in, out string
		amount  uint64
	}{
		{"same asset", "lovelace", "lovelace", 1000000},
		{"zero amount", "lovelace", tokenUnit(), 0},
		{"bad asset_in", "zz", tokenUnit(), 1000000},
		{"overlong asset_out", "lovelace", hex.EncodeToString(tokenPolicy) + strings.Repeat("aa", 33), 1000000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := svc.Quote(context.Background(), c.in, c.out, c.amount)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("err = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

// TestQuoteSelectsBestPool builds two pools for the same pair with different
// reserves and confirms Quote picks the one yielding the larger output.
func TestQuoteSelectsBestPool(t *testing.T) {
	// Hand-build two pool states for the same pair, different liquidity, so the
	// constant-product math gives different outputs for the same input.
	mkPool := func(id string, ada, tok uint64) *shaidex.PoolState {
		return &shaidex.PoolState{
			Protocol: "minswap-v1",
			PoolId:   id,
			AssetX:   shaicommon.AssetAmount{Class: shaicommon.AssetClass{}, Amount: ada},
			AssetY:   shaicommon.AssetAmount{Class: shaicommon.AssetClass{PolicyId: tokenPolicy, Name: []byte("TEST")}, Amount: tok},
			FeeNum:   9970,
			FeeDenom: 10000,
		}
	}
	svc := NewService(&fakeChain{}, "mainnet")
	svc.cached = []*shaidex.PoolState{
		mkPool("shallow", 100000000, 100000000), // 1:1
		mkPool("deep", 100000000, 300000000),    // 1:3 — better for ADA→token
	}
	svc.cachedSet = true
	svc.cachedAt = time.Now()
	svc.now = func() time.Time { return svc.cachedAt } // freeze: keep cache valid

	q, err := svc.Quote(context.Background(), "lovelace", tokenUnit(), 1000000)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if q.PoolID != "deep" {
		t.Errorf("selected pool = %q, want deep (higher output)", q.PoolID)
	}
}

func TestNonMainnetHasNoPools(t *testing.T) {
	svc := NewService(&fakeChain{}, "preview")
	if _, err := svc.Pools(context.Background()); !errors.Is(err, ErrNotMainnet) {
		t.Errorf("Pools err = %v, want ErrNotMainnet", err)
	}
	if _, err := svc.Quote(context.Background(), "lovelace", tokenUnit(), 1000000); !errors.Is(err, ErrNotMainnet) {
		t.Errorf("Quote err = %v, want ErrNotMainnet", err)
	}
}

func TestParseUnit(t *testing.T) {
	p, n, err := parseUnit("lovelace")
	if err != nil || len(p) != 0 || len(n) != 0 {
		t.Errorf("lovelace → (%x, %x, %v), want empty/empty/nil", p, n, err)
	}
	p, n, err = parseUnit(tokenUnit())
	if err != nil {
		t.Fatalf("parseUnit token: %v", err)
	}
	if hex.EncodeToString(p) != hex.EncodeToString(tokenPolicy) {
		t.Errorf("policy = %x, want %x", p, tokenPolicy)
	}
	if string(n) != "TEST" {
		t.Errorf("name = %q, want TEST", n)
	}
	if _, _, err := parseUnit(hex.EncodeToString(tokenPolicy) + strings.Repeat("aa", 33)); err == nil {
		t.Fatal("parseUnit overlong asset name returned nil error")
	}
}
