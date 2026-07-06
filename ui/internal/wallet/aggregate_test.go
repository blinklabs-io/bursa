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

func TestComputeTxDeltaReceived(t *testing.T) {
	mine := map[string]bool{"addr_mine": true}
	inputs := []chain.TxIO{{Address: "addr_other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}}}
	outputs := []chain.TxIO{
		{Address: "addr_mine", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}}},
		{Address: "addr_other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "1800000"}}},
	}
	dir, net, deltas, err := computeTxDelta(inputs, outputs, mine)
	if err != nil {
		t.Fatalf("computeTxDelta: %v", err)
	}
	if dir != TxDirectionReceived {
		t.Fatalf("direction = %v, want received", dir)
	}
	if net != "3000000" {
		t.Fatalf("net = %v, want 3000000", net)
	}
	if len(deltas) != 0 {
		t.Fatalf("deltas = %v, want none", deltas)
	}
}

func TestComputeTxDeltaSent(t *testing.T) {
	mine := map[string]bool{"addr_mine": true}
	inputs := []chain.TxIO{{Address: "addr_mine", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}}}
	outputs := []chain.TxIO{
		{Address: "addr_other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}}},
		{Address: "addr_mine", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "1800000"}}}, // change
	}
	dir, net, _, err := computeTxDelta(inputs, outputs, mine)
	if err != nil {
		t.Fatalf("computeTxDelta: %v", err)
	}
	if dir != TxDirectionSent {
		t.Fatalf("direction = %v, want sent", dir)
	}
	if net != "-3200000" {
		t.Fatalf("net = %v, want -3200000", net)
	}
}

// TestComputeTxDeltaMixedInputNoExternalOutIsReceived covers a
// mixed-input transaction where the wallet contributes one input alongside
// an outside party's input, but every output still lands on the wallet's own
// addresses. hasOwnIn is true here, but classifying this as "sent" would be
// wrong since nothing left the wallet to an outside party; it should be
// treated as a receipt instead.
func TestComputeTxDeltaMixedInputNoExternalOutIsReceived(t *testing.T) {
	mine := map[string]bool{"addr_mine": true}
	inputs := []chain.TxIO{
		{Address: "addr_mine", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}},
		{Address: "addr_other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "2000000"}}},
	}
	outputs := []chain.TxIO{
		{Address: "addr_mine", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "6800000"}}},
	}
	dir, _, _, err := computeTxDelta(inputs, outputs, mine)
	if err != nil {
		t.Fatalf("computeTxDelta: %v", err)
	}
	if dir != TxDirectionReceived {
		t.Fatalf("direction = %v, want received", dir)
	}
}

func TestComputeTxDeltaSelf(t *testing.T) {
	mine := map[string]bool{"addr_a": true, "addr_b": true}
	inputs := []chain.TxIO{{Address: "addr_a", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "5000000"}}}}
	outputs := []chain.TxIO{{Address: "addr_b", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "4800000"}}}}
	dir, net, _, err := computeTxDelta(inputs, outputs, mine)
	if err != nil {
		t.Fatalf("computeTxDelta: %v", err)
	}
	if dir != TxDirectionSelf {
		t.Fatalf("direction = %v, want self", dir)
	}
	if net != "-200000" {
		t.Fatalf("net = %v, want -200000 (fee only)", net)
	}
}

func TestComputeTxDeltaAssetDeltas(t *testing.T) {
	mine := map[string]bool{"addr_mine": true}
	inputs := []chain.TxIO{{Address: "addr_mine", Amount: []chain.Amount{
		{Unit: "lovelace", Quantity: "5000000"},
		{Unit: "tokenA", Quantity: "10"},
	}}}
	outputs := []chain.TxIO{
		{Address: "addr_other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "3000000"}, {Unit: "tokenA", Quantity: "4"}}},
		{Address: "addr_mine", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "1800000"}, {Unit: "tokenA", Quantity: "6"}}},
	}
	dir, _, deltas, err := computeTxDelta(inputs, outputs, mine)
	if err != nil {
		t.Fatalf("computeTxDelta: %v", err)
	}
	if dir != TxDirectionSent {
		t.Fatalf("direction = %v, want sent", dir)
	}
	if len(deltas) != 1 || deltas[0].Unit != "tokenA" || deltas[0].Quantity != "-4" {
		t.Fatalf("deltas = %+v, want [{tokenA -4}]", deltas)
	}
}

func TestComputeTxDeltaOmitsZeroAssetDelta(t *testing.T) {
	// tokenA passes straight through (spent and returned in full): it did not
	// actually move for the wallet, so it should not appear as a delta.
	mine := map[string]bool{"addr_mine": true}
	inputs := []chain.TxIO{{Address: "addr_mine", Amount: []chain.Amount{{Unit: "tokenA", Quantity: "10"}}}}
	outputs := []chain.TxIO{{Address: "addr_mine", Amount: []chain.Amount{{Unit: "tokenA", Quantity: "10"}}}}
	_, _, deltas, err := computeTxDelta(inputs, outputs, mine)
	if err != nil {
		t.Fatalf("computeTxDelta: %v", err)
	}
	if len(deltas) != 0 {
		t.Fatalf("deltas = %v, want none (pass-through)", deltas)
	}
}

func TestTxConfirmations(t *testing.T) {
	cases := []struct {
		name        string
		tip, block  uint64
		wantConf    uint64
		wantPending bool
	}{
		{"pending", 100, 0, 0, true},
		{"tip block itself", 100, 100, 0, false},
		{"one behind tip", 100, 99, 1, false},
		{"tip lagging (defensive)", 50, 60, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf, pending := txConfirmations(c.tip, c.block)
			if conf != c.wantConf || pending != c.wantPending {
				t.Fatalf("txConfirmations(%d,%d) = (%d,%v), want (%d,%v)", c.tip, c.block, conf, pending, c.wantConf, c.wantPending)
			}
		})
	}
}

func TestToTxIOs(t *testing.T) {
	mine := map[string]bool{"addr_mine": true}
	ios := []chain.TxIO{
		{Address: "addr_mine", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "1000000"}}},
		{Address: "addr_other", Amount: []chain.Amount{{Unit: "lovelace", Quantity: "500000"}, {Unit: "tokenA", Quantity: "2"}}},
	}
	out, err := toTxIOs(ios, mine)
	if err != nil {
		t.Fatalf("toTxIOs: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d, want 2", len(out))
	}
	if !out[0].IsMine || out[0].Lovelace != "1000000" {
		t.Fatalf("out[0] = %+v", out[0])
	}
	if out[1].IsMine {
		t.Fatal("out[1] should not be mine")
	}
	if out[1].Lovelace != "500000" || len(out[1].Assets) != 1 || out[1].Assets[0].Unit != "tokenA" {
		t.Fatalf("out[1] = %+v", out[1])
	}
}
