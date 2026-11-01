// Package dex computes Cardano DEX pool prices and swap quotes entirely from
// the embedded node — no external service. It queries the node's loopback
// Blockfrost endpoint for the UTxOs sitting at each supported protocol's pool
// script address, reconstructs the datum + value CBOR each shai parser expects,
// and uses github.com/blinklabs-io/shai/dex to parse pools and price swaps.
//
// Because every input comes from the local node, this requires no
// external-service consent: it never contacts any host but 127.0.0.1.
package dex

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/mary"
	shaicommon "github.com/blinklabs-io/shai/common"
	shaidex "github.com/blinklabs-io/shai/dex"
	"github.com/blinklabs-io/shai/dex/sundaeswap"
)

// ErrNotMainnet is returned when a quote/pools request is made against a node
// that is not on mainnet. shai's pool locators are mainnet-only, so there are
// no pool addresses to query on other networks.
var ErrNotMainnet = errors.New("dex: pool data is only available on mainnet")

// ErrNoRoute is returned by Quote when no pool can swap the requested pair.
var ErrNoRoute = errors.New("dex: no pool found for the requested pair")

// ErrInvalidRequest is returned for malformed quote inputs (bad asset unit,
// zero amount, identical assets, etc.).
var ErrInvalidRequest = errors.New("dex: invalid request")

// cacheTTL is how long a parsed pool snapshot is reused before re-querying the
// node. Pools change every few blocks; a short cache keeps prices fresh while
// avoiding a full re-scan on every request.
const cacheTTL = 15 * time.Second

const (
	// The deployed Minswap pool scripts require one MINSWAP factory marker in
	// every pool output. Its policy and name are fixed by the deployment.
	minswapPoolMarkerUnit = "13aa2accf2e1561723aa26871e071fdf32c867cff7e7d50ad470d62f4d494e53574150"
	// The Minswap V2 authen policy mints exactly one MSP pool validity asset
	// into each pool output, and the pool script keeps it there.
	minswapV2PoolValidityUnit = "f5808c2c990d86da54bfc97d89cee6efa20cd8461616359478d96b4c4d5350"
	// Every Minswap V2 pool output holds this lovelace on top of any ADA
	// reserve (min_pool_ada in the pool script).
	minswapV2MinPoolLovelace = uint64(4_500_000)
)

// chainQuerier is the slice of the chain client the service needs (satisfied by
// *chain.Client); it exists so tests can supply a fake.
type chainQuerier interface {
	AddressUTxOs(ctx context.Context, addr string) ([]chain.UTxO, error)
	TxOutputs(ctx context.Context, txHash string) ([]chain.TxOutput, error)
}

// parser is the subset of a shai protocol parser this service uses.
type parser interface {
	Protocol() string
	ParsePoolDatum(
		datum []byte,
		utxoValue []byte,
		txHash string,
		txIndex uint32,
		slot uint64,
		timestamp time.Time,
	) (*shaidex.PoolState, error)
}

// valueEncoding selects how a parser consumes the reconstructed UTxO value.
type valueEncoding int

const (
	// valueTxOut encodes the value as a CBOR Babbage transaction output, which
	// the parser decodes via ledger.NewTransactionOutputFromCbor. This is what
	// minswap-v1/v2, sundaeswap, splash, cswap, and wingriders expect. (v2/v3
	// pools that read reserves from the datum ignore the value, but a valid
	// output is still cheap to build and harmless.)
	valueTxOut valueEncoding = iota
	// valueAssetMap encodes the value as a CBOR map[string]uint64 keyed by
	// "lovelace" or concatenated policy+name hex. VyFi expects this form.
	valueAssetMap
)

// protocolDef binds a shai parser to its value-encoding convention.
type protocolDef struct {
	parser   parser
	encoding valueEncoding
	identity poolIdentity
}

type poolIdentity int

const (
	identityMinswap poolIdentity = iota
	identityMinswapV2
	identitySundaeV3
)

// Pool is the node-derived view of a single liquidity pool.
type Pool struct {
	Protocol     string  `json:"protocol"`
	PoolID       string  `json:"pool_id"`
	AssetX       string  `json:"asset_x"` // unit: "lovelace" or policy+hexname
	AssetY       string  `json:"asset_y"`
	ReserveX     string  `json:"reserve_x"` // uint64 as decimal string
	ReserveY     string  `json:"reserve_y"`
	PriceXY      float64 `json:"price_xy"` // Y per X
	PriceYX      float64 `json:"price_yx"` // X per Y
	EffectiveFee float64 `json:"effective_fee"`
	TxHash       string  `json:"tx_hash"`
	TxIndex      uint32  `json:"tx_index"`
}

// Quote is the best swap quote for a requested pair/amount, plus the route.
type Quote struct {
	Protocol       string  `json:"protocol"`
	PoolID         string  `json:"pool_id"`
	AssetIn        string  `json:"asset_in"`
	AssetOut       string  `json:"asset_out"`
	AmountIn       string  `json:"amount_in"`  // uint64 as decimal string
	AmountOut      string  `json:"amount_out"` // uint64 as decimal string
	PriceImpactPct float64 `json:"price_impact_pct"`
	EffectiveFee   float64 `json:"effective_fee"`
	Route          string  `json:"route"` // human-readable, e.g. "minswap-v2 lovelace→<asset>"
}

// Service computes pool prices and swap quotes from the embedded node.
type Service struct {
	chain     chainQuerier
	network   string
	protocols []protocolDef

	mu        sync.Mutex
	cached    []*shaidex.PoolState
	cachedSet bool // distinguishes "scanned, found none" from "never scanned"
	cachedAt  time.Time
	now       func() time.Time // injectable clock for tests
}

// NewService builds a DEX service over the given chain querier. network is the
// node's network; pool data is only available on mainnet (shai's locators are
// mainnet-only).
func NewService(c chainQuerier, network string) *Service {
	return &Service{
		chain:     c,
		network:   network,
		protocols: defaultProtocols(),
		now:       time.Now,
	}
}

// defaultProtocols returns the parsers whose pool identity can be authenticated
// from the output. Each parser's pool addresses come from
// shaidex.PoolAddresses. A protocol must not be added without a verified
// identity rule; a script address and parseable datum alone do not prove that
// an output is a spendable protocol pool.
func defaultProtocols() []protocolDef {
	return []protocolDef{
		{parser: shaidex.NewMinswapV1Parser(), encoding: valueTxOut, identity: identityMinswap},
		{parser: shaidex.NewMinswapV2Parser(), encoding: valueTxOut, identity: identityMinswapV2},
		{parser: shaidex.NewSundaeSwapV3Parser(), encoding: valueTxOut, identity: identitySundaeV3},
	}
}

// Pools returns every parseable pool across the supported protocols, with
// prices. Pools that fail to parse (unexpected datum shapes, non-pool UTxOs at
// the script address) are skipped rather than failing the whole request.
func (s *Service) Pools(ctx context.Context) ([]Pool, error) {
	states, err := s.poolStates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Pool, 0, len(states))
	for _, st := range states {
		out = append(out, poolFromState(st))
	}
	// Deterministic order: protocol, then pool id.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].PoolID < out[j].PoolID
	})
	return out, nil
}

// Quote scans every parseable pool that contains both assetIn and assetOut and
// returns the quote with the largest output amount. assetIn/assetOut are units:
// "lovelace" (or "") for ADA, or concatenated policy-id + asset-name hex.
func (s *Service) Quote(ctx context.Context, assetIn, assetOut string, amountIn uint64) (Quote, error) {
	inPolicy, inName, err := parseUnit(assetIn)
	if err != nil {
		return Quote{}, fmt.Errorf("%w: asset_in: %w", ErrInvalidRequest, err)
	}
	outPolicy, outName, err := parseUnit(assetOut)
	if err != nil {
		return Quote{}, fmt.Errorf("%w: asset_out: %w", ErrInvalidRequest, err)
	}
	if normalizeUnit(assetIn) == normalizeUnit(assetOut) {
		return Quote{}, fmt.Errorf("%w: asset_in and asset_out must differ", ErrInvalidRequest)
	}
	if amountIn == 0 {
		return Quote{}, fmt.Errorf("%w: amount_in must be greater than zero", ErrInvalidRequest)
	}

	states, err := s.poolStates(ctx)
	if err != nil {
		return Quote{}, err
	}

	var best Quote
	var bestOut uint64
	found := false
	for _, st := range states {
		// The pool must hold exactly the requested pair (in either orientation).
		if !poolHasPair(st, inPolicy, inName, outPolicy, outName) {
			continue
		}
		amountOut, impact, qerr := st.Quote(inPolicy, inName, amountIn)
		if qerr != nil || amountOut == 0 {
			continue
		}
		if !found || amountOut > bestOut {
			found = true
			bestOut = amountOut
			best = Quote{
				Protocol:       st.Protocol,
				PoolID:         st.PoolId,
				AssetIn:        normalizeUnit(assetIn),
				AssetOut:       normalizeUnit(assetOut),
				AmountIn:       strconv.FormatUint(amountIn, 10),
				AmountOut:      strconv.FormatUint(amountOut, 10),
				PriceImpactPct: impact,
				EffectiveFee:   st.EffectiveFee(),
				Route: fmt.Sprintf("%s %s→%s", st.Protocol,
					normalizeUnit(assetIn), normalizeUnit(assetOut)),
			}
		}
	}
	if !found {
		return Quote{}, ErrNoRoute
	}
	return best, nil
}

// poolStates returns the cached pool snapshot, refreshing it from the node when
// the cache has expired.
//
// The mutex is held across the scan itself (not just the cache read/write), so
// concurrent callers that all land while the cache is expired serialize on one
// scan instead of each kicking off their own: the first caller through refreshes
// the cache, and everyone else that was waiting re-checks the (now fresh) cache
// under the same lock and returns immediately rather than re-scanning. This
// trades a brief block for callers during a cache-miss window against the
// alternative of a full node scan per concurrent request.
func (s *Service) poolStates(ctx context.Context) ([]*shaidex.PoolState, error) {
	if s.network != "mainnet" {
		return nil, ErrNotMainnet
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cachedSet && s.now().Sub(s.cachedAt) < cacheTTL {
		return s.cached, nil
	}

	states, err := s.scan(ctx)
	if err != nil {
		return nil, err
	}

	s.cached = states
	s.cachedSet = true
	s.cachedAt = s.now()
	return states, nil
}

// scan queries the node for every supported protocol's pool UTxOs and parses
// them into pool states.
func (s *Service) scan(ctx context.Context) ([]*shaidex.PoolState, error) {
	var states []*shaidex.PoolState
	// datumCache memoizes a tx's outputs so that multiple pool UTxOs in the same
	// tx (and re-scans of the same address) cost one tx-utxos call.
	datumCache := map[string][]chain.TxOutput{}

	for _, def := range s.protocols {
		for _, addr := range shaidex.PoolAddresses(def.parser.Protocol()) {
			utxos, err := s.chain.AddressUTxOs(ctx, addr)
			if errors.Is(err, chain.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("query pool address %s: %w", addr, err)
			}
			for _, u := range utxos {
				if u.Address != addr {
					continue
				}
				st, ok, err := s.parseUTxO(ctx, def, u, datumCache)
				if err != nil {
					return nil, fmt.Errorf("parse pool utxo %s#%d: %w", u.TxHash, u.OutputIndex, err)
				}
				if ok {
					states = append(states, st)
				}
			}
		}
	}
	return states, nil
}

// parseUTxO converts one node UTxO into a shai PoolState. It returns ok=false
// (with a nil error) for UTxOs that are genuinely not parseable pools (no
// inline datum, unexpected datum shape, a parser that rejects it) so a stray
// non-pool output at the script address is skipped. A non-nil error means the
// node couldn't be queried (a transport failure, not "this isn't a pool"); the
// caller propagates that instead of silently dropping the pool from results.
func (s *Service) parseUTxO(
	ctx context.Context,
	def protocolDef,
	u chain.UTxO,
	datumCache map[string][]chain.TxOutput,
) (*shaidex.PoolState, bool, error) {
	datumHex, amounts, locked, err := inlineDatumFor(ctx, s.chain, u, datumCache)
	if err != nil {
		return nil, false, err
	}
	if datumHex == "" {
		return nil, false, nil
	}
	datum, err := hex.DecodeString(datumHex)
	if err != nil {
		// A datum that isn't valid hex means this UTxO isn't a pool the parser
		// understands, not a node/transport failure -- deliberately swallowed.
		return nil, false, nil //nolint:nilerr // see parseUTxO doc comment
	}
	if !validPoolIdentity(def.identity, datum, u.Address, locked) {
		return nil, false, nil
	}
	if u.OutputIndex < 0 || uint64(u.OutputIndex) > math.MaxUint32 {
		return nil, false, nil
	}
	value, err := encodeValue(def.encoding, amounts)
	if err != nil {
		// Same as above: a value the encoder can't build (bad quantity string)
		// means this isn't a well-formed pool UTxO, not a transport failure.
		return nil, false, nil //nolint:nilerr // see parseUTxO doc comment
	}
	st, err := def.parser.ParsePoolDatum(
		datum,
		value,
		u.TxHash,
		uint32(u.OutputIndex),
		0,
		time.Time{}, //nolint:gosec // range checked above
	)
	if err != nil || st == nil {
		// The parser rejecting the datum shape means this isn't a pool this
		// protocol's parser recognizes, not a transport failure.
		return nil, false, nil //nolint:nilerr // see parseUTxO doc comment
	}
	if !reservesMatchLocked(def.parser.Protocol(), st, locked) {
		return nil, false, nil
	}
	return st, true, nil
}

func lockedValue(amounts []chain.Amount) (map[string]uint64, bool) {
	ret := make(map[string]uint64, len(amounts))
	for _, amount := range amounts {
		unit := amount.Unit
		if unit == "" {
			unit = "lovelace"
		}
		if unit != "lovelace" {
			policy, name, err := splitUnit(unit)
			if err != nil || len(policy) != 28 || len(name) > 32 ||
				hex.EncodeToString(policy)+hex.EncodeToString(name) != unit {
				return nil, false
			}
		}
		qty, err := strconv.ParseUint(amount.Quantity, 10, 64)
		if err != nil || qty == 0 {
			return nil, false
		}
		if _, exists := ret[unit]; exists {
			return nil, false
		}
		ret[unit] = qty
	}
	if ret["lovelace"] == 0 {
		return nil, false
	}
	return ret, true
}

func validPoolIdentity(
	kind poolIdentity,
	datum []byte,
	address string,
	locked map[string]uint64,
) bool {
	switch kind {
	case identityMinswap:
		return locked[minswapPoolMarkerUnit] == 1
	case identityMinswapV2:
		return locked[minswapV2PoolValidityUnit] == 1
	case identitySundaeV3:
		var poolDatum sundaeswap.V3PoolDatum
		if _, err := cbor.Decode(datum, &poolDatum); err != nil ||
			len(poolDatum.Identifier) != 28 ||
			!validSundaeV3Fees(poolDatum) {
			return false
		}
		addr, err := lcommon.NewAddress(address)
		if err != nil || addr.Type()&lcommon.AddressTypeScriptBit == 0 {
			return false
		}
		policy := addr.PaymentKeyHash()
		unit := hex.EncodeToString(policy[:]) + "000de140" + hex.EncodeToString(poolDatum.Identifier)
		return locked[unit] == 1
	default:
		return false
	}
}

func validSundaeV3Fees(datum sundaeswap.V3PoolDatum) bool {
	bidNum := datum.BidFeesPer10Thousand.Numerator
	bidDen := datum.BidFeesPer10Thousand.Denominator
	askNum := datum.AskFeesPer10Thousand.Numerator
	askDen := datum.AskFeesPer10Thousand.Denominator
	if bidDen == 0 || askDen == 0 {
		return false
	}

	bidTerm, ok := checkedMul(bidNum, askDen)
	if !ok {
		return false
	}
	askTerm, ok := checkedMul(askNum, bidDen)
	if !ok {
		return false
	}
	avgNum, ok := checkedAdd(bidTerm, askTerm)
	if !ok {
		return false
	}
	twiceBidDen, ok := checkedMul(2, bidDen)
	if !ok {
		return false
	}
	avgDen, ok := checkedMul(twiceBidDen, askDen)
	if !ok || avgDen == 0 || avgNum > avgDen {
		return false
	}
	scaledFee, ok := checkedMul(sundaeswap.FeeDenom, avgDen-avgNum)
	if !ok {
		return false
	}
	effectiveFee := scaledFee / avgDen
	return effectiveFee > 0 && effectiveFee <= sundaeswap.FeeDenom
}

func checkedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func checkedAdd(a, b uint64) (uint64, bool) {
	if a > math.MaxUint64-b {
		return 0, false
	}
	return a + b, true
}

func reservesMatchLocked(protocol string, state *shaidex.PoolState, locked map[string]uint64) bool {
	if state.AssetX.Amount == 0 || state.AssetY.Amount == 0 ||
		bytes.Equal(state.AssetX.Class.PolicyId, state.AssetY.Class.PolicyId) &&
			bytes.Equal(state.AssetX.Class.Name, state.AssetY.Class.Name) {
		return false
	}
	if protocol == "minswap-v2" &&
		!state.AssetX.IsLovelace() && !state.AssetY.IsLovelace() &&
		locked["lovelace"] != minswapV2MinPoolLovelace {
		return false
	}
	return reserveMatches(protocol, state.AssetX, locked) &&
		reserveMatches(protocol, state.AssetY, locked)
}

// reserveMatches reports whether the locked value backs a parsed reserve.
// Parsers that read reserves from the value must match it exactly. Minswap V2
// prices from datum reserves, and its pool script lets the value exceed them
// by the fee-sharing amount accrued since the last withdrawal.
func reserveMatches(
	protocol string,
	reserve shaicommon.AssetAmount,
	locked map[string]uint64,
) bool {
	unit := hex.EncodeToString(reserve.Class.PolicyId) + hex.EncodeToString(reserve.Class.Name)
	if reserve.IsLovelace() {
		unit = "lovelace"
	}
	if protocol != "minswap-v2" {
		return locked[unit] == reserve.Amount
	}
	held := locked[unit]
	if reserve.IsLovelace() {
		if held < minswapV2MinPoolLovelace {
			return false
		}
		held -= minswapV2MinPoolLovelace
	}
	return held >= reserve.Amount
}

// inlineDatumFor returns the authoritative inline datum and value for a UTxO.
// The transaction output must match the address UTxO's index, address, and
// canonical value before its datum is trusted. A tx-utxos lookup that reports
// the transaction doesn't exist (chain.ErrNotFound) yields "" so the stray
// UTxO is skipped; any other error is propagated and left out of the cache.
func inlineDatumFor(
	ctx context.Context,
	c chainQuerier,
	u chain.UTxO,
	cache map[string][]chain.TxOutput,
) (string, []chain.Amount, map[string]uint64, error) {
	locked, ok := lockedValue(u.Amount)
	if !ok {
		return "", nil, nil, nil
	}
	outs, cached := cache[u.TxHash]
	if !cached {
		var err error
		outs, err = c.TxOutputs(ctx, u.TxHash)
		if err != nil {
			if errors.Is(err, chain.ErrNotFound) {
				cache[u.TxHash] = nil // negative-cache: no such tx; don't retry in this scan
				return "", nil, nil, nil
			}
			return "", nil, nil, fmt.Errorf("query tx outputs for %s: %w", u.TxHash, err)
		}
		cache[u.TxHash] = outs
	}
	var match *chain.TxOutput
	for i := range outs {
		o := &outs[i]
		if o.OutputIndex != u.OutputIndex {
			continue
		}
		if match != nil {
			return "", nil, nil, nil
		}
		match = o
	}
	if match == nil || match.Address != u.Address ||
		match.InlineDatum == nil || *match.InlineDatum == "" {
		return "", nil, nil, nil
	}
	authoritativeLocked, ok := lockedValue(match.Amount)
	if !ok || !equalLockedValue(locked, authoritativeLocked) {
		return "", nil, nil, nil
	}
	return *match.InlineDatum, match.Amount, authoritativeLocked, nil
}

func equalLockedValue(a, b map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for unit, quantity := range a {
		if b[unit] != quantity {
			return false
		}
	}
	return true
}

// encodeValue reconstructs the CBOR UTxO value a shai parser expects from the
// node's flat amount list.
func encodeValue(enc valueEncoding, amounts []chain.Amount) ([]byte, error) {
	switch enc {
	case valueAssetMap:
		return encodeAssetMap(amounts)
	case valueTxOut:
		return encodeTxOut(amounts)
	default:
		return encodeTxOut(amounts)
	}
}

// placeholderAddress is the OutputAddress used in the reconstructed output. The
// txOut-based parsers decode only the value (reserves) from the CBOR and never
// inspect the address, so a fixed valid address keeps encoding independent of
// whether the node's bech32 address round-trips through gouroboros (Minswap V1's
// locator address, for one, does not re-parse cleanly).
func placeholderAddress() (lcommon.Address, error) {
	return lcommon.NewAddressFromParts(
		lcommon.AddressTypeKeyKey,
		lcommon.AddressNetworkMainnet,
		make([]byte, 28),
		make([]byte, 28),
	)
}

// encodeTxOut builds a CBOR Babbage transaction output carrying the amount list,
// matching what ledger.NewTransactionOutputFromCbor (used by most parsers) reads.
func encodeTxOut(amounts []chain.Amount) ([]byte, error) {
	addr, err := placeholderAddress()
	if err != nil {
		return nil, fmt.Errorf("build placeholder address: %w", err)
	}

	var lovelace uint64
	// MultiAssetTypeOutput is *big.Int; the value map must use it directly.
	multiAssetData := map[lcommon.Blake2b224]map[cbor.ByteString]lcommon.MultiAssetTypeOutput{}
	for _, a := range amounts {
		qty, err := strconv.ParseUint(a.Quantity, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse quantity %q: %w", a.Quantity, err)
		}
		if a.Unit == "lovelace" || a.Unit == "" {
			lovelace = qty
			continue
		}
		policy, name, err := splitUnit(a.Unit)
		if err != nil {
			return nil, err
		}
		ph := lcommon.NewBlake2b224(policy)
		if _, ok := multiAssetData[ph]; !ok {
			multiAssetData[ph] = map[cbor.ByteString]lcommon.MultiAssetTypeOutput{}
		}
		multiAssetData[ph][cbor.NewByteString(name)] = new(big.Int).SetUint64(qty)
	}

	var multiAsset *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput]
	if len(multiAssetData) > 0 {
		tmp := lcommon.NewMultiAsset(multiAssetData)
		multiAsset = &tmp
	}

	txOut := babbage.BabbageTransactionOutput{
		OutputAddress: addr,
		OutputAmount: mary.MaryTransactionOutputValue{
			Amount: lovelace,
			Assets: multiAsset,
		},
	}
	return cbor.Encode(&txOut)
}

// encodeAssetMap builds the CBOR map[string]uint64 form VyFi expects: keys are
// "lovelace" or concatenated policy+name hex, values are amounts.
func encodeAssetMap(amounts []chain.Amount) ([]byte, error) {
	m := make(map[string]uint64, len(amounts))
	for _, a := range amounts {
		qty, err := strconv.ParseUint(a.Quantity, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse quantity %q: %w", a.Quantity, err)
		}
		unit := a.Unit
		if unit == "" {
			unit = "lovelace"
		}
		m[unit] = qty
	}
	return cbor.Encode(m)
}

// poolFromState renders a shai PoolState into the API-facing Pool view.
func poolFromState(st *shaidex.PoolState) Pool {
	return Pool{
		Protocol:     st.Protocol,
		PoolID:       st.PoolId,
		AssetX:       unitFromClass(st.AssetX.Class),
		AssetY:       unitFromClass(st.AssetY.Class),
		ReserveX:     strconv.FormatUint(st.AssetX.Amount, 10),
		ReserveY:     strconv.FormatUint(st.AssetY.Amount, 10),
		PriceXY:      st.PriceXY(),
		PriceYX:      st.PriceYX(),
		EffectiveFee: st.EffectiveFee(),
		TxHash:       st.TxHash,
		TxIndex:      st.TxIndex,
	}
}

// poolHasPair reports whether the pool's two assets are exactly the requested
// in/out pair (in either orientation).
func poolHasPair(st *shaidex.PoolState, inPolicy, inName, outPolicy, outName []byte) bool {
	x := st.AssetX.Class
	y := st.AssetY.Class
	matchesIn := func(c shaicommon.AssetClass) bool {
		return bytes.Equal(c.PolicyId, inPolicy) && bytes.Equal(c.Name, inName)
	}
	matchesOut := func(c shaicommon.AssetClass) bool {
		return bytes.Equal(c.PolicyId, outPolicy) && bytes.Equal(c.Name, outName)
	}
	return (matchesIn(x) && matchesOut(y)) || (matchesIn(y) && matchesOut(x))
}

// unitFromClass renders a shai asset class as a unit string ("lovelace" or
// policy+hexname).
func unitFromClass(c shaicommon.AssetClass) string {
	if len(c.PolicyId) == 0 && len(c.Name) == 0 {
		return "lovelace"
	}
	return hex.EncodeToString(c.PolicyId) + hex.EncodeToString(c.Name)
}

// normalizeUnit canonicalizes an asset unit so the empty string and "lovelace"
// both render as "lovelace".
func normalizeUnit(unit string) string {
	if unit == "" || unit == "lovelace" {
		return "lovelace"
	}
	return unit
}

// parseUnit splits an asset unit into policy id + name bytes. "lovelace" and ""
// both yield empty policy + empty name (ADA).
func parseUnit(unit string) (policy, name []byte, err error) {
	if unit == "" || unit == "lovelace" {
		return nil, nil, nil
	}
	return splitUnit(unit)
}

// splitUnit splits a concatenated policy+name hex unit. The policy id is the
// first 28 bytes (56 hex chars); the remainder is the asset name.
func splitUnit(unit string) (policy, name []byte, err error) {
	const (
		policyIDHexLen  = 56
		maxAssetNameHex = 64
	)
	if len(unit) < policyIDHexLen {
		return nil, nil, fmt.Errorf("asset unit too short: %q", unit)
	}
	if len(unit) > policyIDHexLen+maxAssetNameHex {
		return nil, nil, fmt.Errorf("asset unit too long: %q", unit)
	}
	policy, err = hex.DecodeString(unit[:policyIDHexLen])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid policy id in unit %q: %w", unit, err)
	}
	name, err = hex.DecodeString(unit[policyIDHexLen:])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid asset name in unit %q: %w", unit, err)
	}
	return policy, name, nil
}
