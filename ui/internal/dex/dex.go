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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	"github.com/blinklabs-io/gouroboros/ledger/mary"
	shaicommon "github.com/blinklabs-io/shai/common"
	shaidex "github.com/blinklabs-io/shai/dex"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
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
}

// Pool is the node-derived view of a single liquidity pool.
type Pool struct {
	Protocol     string `json:"protocol"`
	PoolID       string `json:"pool_id"`
	AssetX       string `json:"asset_x"` // unit: "lovelace" or policy+hexname
	AssetY       string `json:"asset_y"`
	ReserveX     string `json:"reserve_x"` // uint64 as decimal string
	ReserveY     string `json:"reserve_y"`
	PriceXY      float64 `json:"price_xy"` // Y per X
	PriceYX      float64 `json:"price_yx"` // X per Y
	EffectiveFee float64 `json:"effective_fee"`
	TxHash       string `json:"tx_hash"`
	TxIndex      uint32 `json:"tx_index"`
}

// Quote is the best swap quote for a requested pair/amount, plus the route.
type Quote struct {
	Protocol       string  `json:"protocol"`
	PoolID         string  `json:"pool_id"`
	AssetIn        string  `json:"asset_in"`
	AssetOut       string  `json:"asset_out"`
	AmountIn       string  `json:"amount_in"`        // uint64 as decimal string
	AmountOut      string  `json:"amount_out"`       // uint64 as decimal string
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
	cachAt    time.Time
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

// defaultProtocols returns the supported shai parsers paired with their value
// encoding. Each parser's pool addresses come from shaidex.PoolAddresses.
func defaultProtocols() []protocolDef {
	return []protocolDef{
		{parser: shaidex.NewMinswapV1Parser(), encoding: valueTxOut},
		{parser: shaidex.NewMinswapV2Parser(), encoding: valueTxOut},
		{parser: shaidex.NewSundaeSwapV1Parser(), encoding: valueTxOut},
		{parser: shaidex.NewSundaeSwapV3Parser(), encoding: valueTxOut},
		{parser: shaidex.NewSplashV1Parser(), encoding: valueTxOut},
		{parser: shaidex.NewWingRidersV2Parser(), encoding: valueTxOut},
		{parser: shaidex.NewCSwapParser(), encoding: valueTxOut},
		{parser: shaidex.NewVyFiParser(), encoding: valueAssetMap},
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
		return Quote{}, fmt.Errorf("%w: asset_in: %v", ErrInvalidRequest, err)
	}
	outPolicy, outName, err := parseUnit(assetOut)
	if err != nil {
		return Quote{}, fmt.Errorf("%w: asset_out: %v", ErrInvalidRequest, err)
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
func (s *Service) poolStates(ctx context.Context) ([]*shaidex.PoolState, error) {
	if s.network != "mainnet" {
		return nil, ErrNotMainnet
	}
	s.mu.Lock()
	if s.cachedSet && s.now().Sub(s.cachAt) < cacheTTL {
		cached := s.cached
		s.mu.Unlock()
		return cached, nil
	}
	s.mu.Unlock()

	states, err := s.scan(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.cached = states
	s.cachedSet = true
	s.cachAt = s.now()
	s.mu.Unlock()
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
				st, ok := s.parseUTxO(ctx, def, u, datumCache)
				if ok {
					states = append(states, st)
				}
			}
		}
	}
	return states, nil
}

// parseUTxO converts one node UTxO into a shai PoolState. It returns ok=false
// (silently) for UTxOs that are not parseable pools (no inline datum, unexpected
// datum shape) so a stray non-pool output at the script address is skipped.
func (s *Service) parseUTxO(
	ctx context.Context,
	def protocolDef,
	u chain.UTxO,
	datumCache map[string][]chain.TxOutput,
) (*shaidex.PoolState, bool) {
	datumHex := inlineDatumFor(ctx, s.chain, u, datumCache)
	if datumHex == "" {
		return nil, false
	}
	datum, err := hex.DecodeString(datumHex)
	if err != nil {
		return nil, false
	}
	value, err := encodeValue(def.encoding, u.Amount)
	if err != nil {
		return nil, false
	}
	st, err := def.parser.ParsePoolDatum(
		datum, value, u.TxHash, uint32(u.OutputIndex), 0, time.Time{},
	)
	if err != nil || st == nil {
		return nil, false
	}
	return st, true
}

// inlineDatumFor returns the inline datum hex for a UTxO. The address-utxos
// endpoint never populates the inline datum, so we always recover it from the
// transaction's outputs (tx-utxos endpoint), matching by output index.
func inlineDatumFor(
	ctx context.Context,
	c chainQuerier,
	u chain.UTxO,
	cache map[string][]chain.TxOutput,
) string {
	if u.InlineDatum != nil && *u.InlineDatum != "" {
		return *u.InlineDatum
	}
	outs, ok := cache[u.TxHash]
	if !ok {
		var err error
		outs, err = c.TxOutputs(ctx, u.TxHash)
		if err != nil {
			outs = nil // negative-cache: don't retry this tx in the same scan
		}
		cache[u.TxHash] = outs
	}
	for _, o := range outs {
		if o.OutputIndex == u.OutputIndex && o.InlineDatum != nil {
			return *o.InlineDatum
		}
	}
	return ""
}

// encodeValue reconstructs the CBOR UTxO value a shai parser expects from the
// node's flat amount list.
func encodeValue(enc valueEncoding, amounts []chain.Amount) ([]byte, error) {
	switch enc {
	case valueAssetMap:
		return encodeAssetMap(amounts)
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
		return bytesEqual(c.PolicyId, inPolicy) && bytesEqual(c.Name, inName)
	}
	matchesOut := func(c shaicommon.AssetClass) bool {
		return bytesEqual(c.PolicyId, outPolicy) && bytesEqual(c.Name, outName)
	}
	return (matchesIn(x) && matchesOut(y)) || (matchesIn(y) && matchesOut(x))
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
	if len(unit) < 56 {
		return nil, nil, fmt.Errorf("asset unit too short: %q", unit)
	}
	policy, err = hex.DecodeString(unit[:56])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid policy id in unit %q: %w", unit, err)
	}
	name, err = hex.DecodeString(unit[56:])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid asset name in unit %q: %w", unit, err)
	}
	return policy, name, nil
}
