package wallet

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

// ErrInvalidAmountQuantity is returned when chain data contains an unparsable
// or negative asset quantity.
var ErrInvalidAmountQuantity = errors.New("wallet: invalid amount quantity")

// AssetBalance is a summed native-asset quantity (decimal string).
type AssetBalance struct {
	Unit     string `json:"unit"`
	Quantity string `json:"quantity"`
}

// Balance is the aggregated wallet balance: total lovelace + native assets.
type Balance struct {
	Lovelace string         `json:"lovelace"`
	Assets   []AssetBalance `json:"assets"`
}

// TxDirection classifies a transaction relative to the wallet's own addresses.
type TxDirection string

const (
	// TxDirectionReceived is a transaction that pays the wallet without
	// spending any of its own inputs.
	TxDirectionReceived TxDirection = "received"
	// TxDirectionSent is a transaction that spends at least one of the
	// wallet's own inputs to pay an outside address; change returned to the
	// wallet does not change this classification.
	TxDirectionSent TxDirection = "sent"
	// TxDirectionSelf is a transaction whose every input and output belongs
	// to the wallet's own addresses (e.g. UTxO consolidation between the
	// wallet's own addresses).
	TxDirectionSelf TxDirection = "self"
)

// AssetDelta is a signed per-native-asset quantity change (decimal string;
// negative means the wallet's holdings of that asset decreased).
type AssetDelta struct {
	Unit     string `json:"unit"`
	Quantity string `json:"quantity"`
}

// Tx is one entry of the merged transaction history, enriched with its
// direction, net ADA/asset deltas, fee, and confirmation count relative to
// the active wallet's own addresses.
type Tx struct {
	TxHash      string `json:"tx_hash"`
	TxIndex     int    `json:"tx_index"`
	BlockHeight uint64 `json:"block_height"`
	BlockTime   int64  `json:"block_time"`
	// Direction, NetLovelace, AssetDeltas, and Fee are populated by
	// enrichment (see Service.Transactions / Service.TransactionDetail); a Tx
	// built by MergeTransactions alone leaves them zero-valued.
	Direction   TxDirection  `json:"direction"`
	NetLovelace string       `json:"net_lovelace"`
	AssetDeltas []AssetDelta `json:"asset_deltas"`
	Fee         string       `json:"fee"`
	// Confirmations is the node's chain-tip height minus this transaction's
	// block height. Pending is true (and Confirmations 0) when the
	// transaction has not yet been included in a block.
	Confirmations uint64 `json:"confirmations"`
	Pending       bool   `json:"pending"`
}

// TxIO is one input or output of a transaction detail view: the address, its
// lovelace + native-asset amounts, and whether the address belongs to the
// active wallet.
type TxIO struct {
	Address  string         `json:"address"`
	Lovelace string         `json:"lovelace"`
	Assets   []AssetBalance `json:"assets"`
	IsMine   bool           `json:"is_mine"`
}

// TxDetail is the drill-down view of a single transaction: its enriched
// summary (Tx) plus the full input/output breakdown.
type TxDetail struct {
	Tx
	Inputs  []TxIO `json:"inputs"`
	Outputs []TxIO `json:"outputs"`
}

// AggregateBalance sums all UTxO amounts by unit, separating lovelace from
// native assets. Quantities are summed with big.Int (token amounts can exceed
// uint64). Assets are sorted by unit for deterministic output.
func AggregateBalance(utxos []chain.UTxO) (Balance, error) {
	lovelace := new(big.Int)
	assets := map[string]*big.Int{}
	for _, u := range utxos {
		for _, a := range u.Amount {
			n, ok := new(big.Int).SetString(a.Quantity, 10)
			if !ok || n.Sign() < 0 {
				return Balance{}, fmt.Errorf("%w: unit %q quantity %q", ErrInvalidAmountQuantity, a.Unit, a.Quantity)
			}
			if a.Unit == "lovelace" {
				lovelace.Add(lovelace, n)
				continue
			}
			if assets[a.Unit] == nil {
				assets[a.Unit] = new(big.Int)
			}
			assets[a.Unit].Add(assets[a.Unit], n)
		}
	}
	units := make([]string, 0, len(assets))
	for u := range assets {
		units = append(units, u)
	}
	sort.Strings(units)
	out := make([]AssetBalance, 0, len(units))
	for _, u := range units {
		out = append(out, AssetBalance{Unit: u, Quantity: assets[u].String()})
	}
	return Balance{Lovelace: lovelace.String(), Assets: out}, nil
}

// MergeTransactions flattens per-address transaction lists, deduplicates by
// tx hash, and returns them newest-first (by block height, then tx index).
func MergeTransactions(perAddress [][]chain.AddressTx) []Tx {
	seen := map[string]Tx{}
	for _, list := range perAddress {
		for _, t := range list {
			if _, ok := seen[t.TxHash]; !ok {
				seen[t.TxHash] = Tx{TxHash: t.TxHash, TxIndex: t.TxIndex, BlockHeight: t.BlockHeight, BlockTime: t.BlockTime}
			}
		}
	}
	out := make([]Tx, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BlockHeight != out[j].BlockHeight {
			return out[i].BlockHeight > out[j].BlockHeight
		}
		if out[i].TxIndex != out[j].TxIndex {
			return out[i].TxIndex > out[j].TxIndex
		}
		return out[i].TxHash > out[j].TxHash
	})
	return out
}

// ownedBalance sums the side (inputs or outputs) of a transaction that
// belongs to the wallet's own addresses (mine), reusing AggregateBalance's
// summation. It also reports whether any entry on that side is the wallet's
// own (hasOwn) and whether any belongs to an outside address (hasExternal) —
// together these classify a transaction's direction.
func ownedBalance(ios []chain.TxIO, mine map[string]bool) (bal Balance, hasOwn, hasExternal bool, err error) {
	owned := make([]chain.UTxO, 0, len(ios))
	for _, io := range ios {
		if mine[io.Address] {
			hasOwn = true
			owned = append(owned, chain.UTxO{Amount: io.Amount})
		} else {
			hasExternal = true
		}
	}
	bal, err = AggregateBalance(owned)
	return bal, hasOwn, hasExternal, err
}

// computeTxDelta diffs a transaction's inputs and outputs against the
// wallet's own addresses (mine): the direction relative to the wallet, the
// net lovelace change (signed decimal string), and the per-native-asset
// deltas (zero-net units omitted).
func computeTxDelta(inputs, outputs []chain.TxIO, mine map[string]bool) (TxDirection, string, []AssetDelta, error) {
	inBal, hasOwnIn, hasExternalIn, err := ownedBalance(inputs, mine)
	if err != nil {
		return "", "", nil, err
	}
	outBal, hasOwnOut, hasExternalOut, err := ownedBalance(outputs, mine)
	if err != nil {
		return "", "", nil, err
	}

	direction := TxDirectionReceived
	switch {
	case hasOwnIn && !hasExternalIn && !hasExternalOut:
		// Every input and output touching this transaction is the wallet's
		// own: an internal reorganization (e.g. UTxO consolidation), not a
		// payment to or from an outside party.
		direction = TxDirectionSelf
	case hasOwnIn && hasExternalOut:
		// The wallet funded the transaction and paid an outside address;
		// change coming back to it does not make this a "received"
		// transaction. Requiring hasExternalOut (rather than just hasOwnIn)
		// matters for a mixed-input transaction where the wallet contributed
		// one input alongside an outside party's but every output still
		// comes back to the wallet's own addresses — that is a receipt, not
		// a send.
		direction = TxDirectionSent
	case hasOwnOut:
		direction = TxDirectionReceived
	}

	netLovelace, err := subtractDecimal(outBal.Lovelace, inBal.Lovelace)
	if err != nil {
		return "", "", nil, err
	}
	deltas, err := diffAssetBalances(outBal.Assets, inBal.Assets)
	if err != nil {
		return "", "", nil, err
	}
	return direction, netLovelace, deltas, nil
}

// subtractDecimal returns a-b as a decimal string. a and b are always
// produced by AggregateBalance (validated non-negative decimal digit
// strings), so a parse failure here indicates a caller bug rather than bad
// chain data.
func subtractDecimal(a, b string) (string, error) {
	av, ok := new(big.Int).SetString(a, 10)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrInvalidAmountQuantity, a)
	}
	bv, ok := new(big.Int).SetString(b, 10)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrInvalidAmountQuantity, b)
	}
	return new(big.Int).Sub(av, bv).String(), nil
}

// diffAssetBalances returns the per-unit delta (out minus in) across two
// asset-balance lists, sorted by unit, omitting units whose net delta is
// zero (a pass-through asset the transaction didn't actually move for the
// wallet).
func diffAssetBalances(out, in []AssetBalance) ([]AssetDelta, error) {
	outQty := make(map[string]string, len(out))
	for _, a := range out {
		outQty[a.Unit] = a.Quantity
	}
	inQty := make(map[string]string, len(in))
	for _, a := range in {
		inQty[a.Unit] = a.Quantity
	}
	unitSet := make(map[string]bool, len(outQty)+len(inQty))
	for u := range outQty {
		unitSet[u] = true
	}
	for u := range inQty {
		unitSet[u] = true
	}
	units := make([]string, 0, len(unitSet))
	for u := range unitSet {
		units = append(units, u)
	}
	sort.Strings(units)

	deltas := make([]AssetDelta, 0, len(units))
	for _, u := range units {
		o, ok := outQty[u]
		if !ok {
			o = "0"
		}
		i, ok := inQty[u]
		if !ok {
			i = "0"
		}
		d, err := subtractDecimal(o, i)
		if err != nil {
			return nil, err
		}
		if d == "0" {
			continue
		}
		deltas = append(deltas, AssetDelta{Unit: u, Quantity: d})
	}
	return deltas, nil
}

// txConfirmations reports a transaction's confirmation count and whether it
// is still pending (not yet included in a block, blockHeight == 0). It
// mirrors dingo's own block-confirmation convention: confirmations = tip
// height minus the transaction's block height (0 if the tip has not yet
// caught up to it, which can happen transiently against a syncing node).
func txConfirmations(tipHeight, blockHeight uint64) (confirmations uint64, pending bool) {
	if blockHeight == 0 {
		return 0, true
	}
	if tipHeight < blockHeight {
		return 0, false
	}
	return tipHeight - blockHeight, false
}

// toTxIOs converts a transaction's raw inputs/outputs into the detail view,
// marking which belong to the wallet's own addresses (mine).
func toTxIOs(ios []chain.TxIO, mine map[string]bool) ([]TxIO, error) {
	out := make([]TxIO, 0, len(ios))
	for _, io := range ios {
		bal, err := AggregateBalance([]chain.UTxO{{Amount: io.Amount}})
		if err != nil {
			return nil, err
		}
		out = append(out, TxIO{
			Address:  io.Address,
			Lovelace: bal.Lovelace,
			Assets:   bal.Assets,
			IsMine:   mine[io.Address],
		})
	}
	return out, nil
}
