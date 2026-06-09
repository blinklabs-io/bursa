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

// Tx is one entry of the merged transaction history.
type Tx struct {
	TxHash      string `json:"tx_hash"`
	TxIndex     int    `json:"tx_index"`
	BlockHeight uint64 `json:"block_height"`
	BlockTime   int64  `json:"block_time"`
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
