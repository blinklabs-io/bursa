package wallet

import (
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
)

func TestAggregateBalance(t *testing.T) {
	utxos := []chain.UTxO{
		{Amount: []chain.Amount{{Unit: "lovelace", Quantity: "1000000"}, {Unit: "tokenB", Quantity: "5"}}},
		{Amount: []chain.Amount{{Unit: "lovelace", Quantity: "2500000"}, {Unit: "tokenA", Quantity: "3"}, {Unit: "tokenB", Quantity: "2"}}},
	}
	bal, err := AggregateBalance(utxos)
	if err != nil {
		t.Fatalf("AggregateBalance: %v", err)
	}
	if bal.Lovelace != "3500000" {
		t.Fatalf("lovelace = %q, want 3500000", bal.Lovelace)
	}
	if len(bal.Assets) != 2 {
		t.Fatalf("got %d assets, want 2 (%+v)", len(bal.Assets), bal.Assets)
	}
	if bal.Assets[0].Unit != "tokenA" || bal.Assets[0].Quantity != "3" {
		t.Fatalf("assets[0] = %+v, want {tokenA 3}", bal.Assets[0])
	}
	if bal.Assets[1].Unit != "tokenB" || bal.Assets[1].Quantity != "7" {
		t.Fatalf("assets[1] = %+v, want {tokenB 7}", bal.Assets[1])
	}
}

func TestAggregateBalanceEmpty(t *testing.T) {
	bal, err := AggregateBalance(nil)
	if err != nil {
		t.Fatalf("AggregateBalance: %v", err)
	}
	if bal.Lovelace != "0" || len(bal.Assets) != 0 {
		t.Fatalf("empty balance = %+v, want lovelace 0 / no assets", bal)
	}
}

func TestAggregateBalanceInvalidQuantity(t *testing.T) {
	for _, quantity := range []string{"bad", "-1"} {
		t.Run(quantity, func(t *testing.T) {
			_, err := AggregateBalance([]chain.UTxO{
				{Amount: []chain.Amount{{Unit: "lovelace", Quantity: quantity}}},
			})
			if !errors.Is(err, ErrInvalidAmountQuantity) {
				t.Fatalf("AggregateBalance err = %v, want ErrInvalidAmountQuantity", err)
			}
		})
	}
}

func TestMergeTransactions(t *testing.T) {
	a := []chain.AddressTx{
		{TxHash: "t1", TxIndex: 0, BlockHeight: 10, BlockTime: 100},
		{TxHash: "t2", TxIndex: 1, BlockHeight: 20, BlockTime: 200},
		{TxHash: "z-same-block-lower-index", TxIndex: 0, BlockHeight: 20, BlockTime: 200},
	}
	b := []chain.AddressTx{
		{TxHash: "t2", TxIndex: 1, BlockHeight: 20, BlockTime: 200},
		{TxHash: "t3", TxIndex: 0, BlockHeight: 30, BlockTime: 300},
	}
	got := MergeTransactions([][]chain.AddressTx{a, b})
	if len(got) != 4 {
		t.Fatalf("got %d txs, want 4 (dedup): %+v", len(got), got)
	}
	if got[0].TxHash != "t3" || got[1].TxHash != "t2" || got[2].TxHash != "z-same-block-lower-index" || got[3].TxHash != "t1" {
		t.Fatalf("order = %v, want t3,t2,z-same-block-lower-index,t1", []string{got[0].TxHash, got[1].TxHash, got[2].TxHash, got[3].TxHash})
	}
}
