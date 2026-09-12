// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bursa

import (
	"math"
	"testing"
)

func TestTransactionID(t *testing.T) {
	id, err := TransactionID(mustTestTx(t))
	if err != nil {
		t.Fatalf("TransactionID: %v", err)
	}
	if len(id) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(id), id)
	}
	if id != "c599a51234a1ee8570b60438d7eedd55a6fa1ed3cf3b6c1da01fb1703762632b" {
		t.Fatalf("unexpected txid %q", id)
	}
}

func TestInspectTransaction(t *testing.T) {
	insp, err := InspectTransaction(mustTestTx(t))
	if err != nil {
		t.Fatalf("InspectTransaction: %v", err)
	}
	if insp.TxId == "" {
		t.Fatalf("missing tx id")
	}
	if insp.Era != "Conway" {
		t.Fatalf("expected Conway era, got %q", insp.Era)
	}
	if len(insp.Inputs) == 0 {
		t.Fatalf("expected at least one input")
	}
	if len(insp.Outputs) == 0 {
		t.Fatalf("expected at least one output")
	}
	if insp.SizeBytes == 0 {
		t.Fatalf("expected non-zero size")
	}
}

func TestMinFee(t *testing.T) {
	params := ProtocolParams{TxFeePerByte: 44, TxFeeFixed: 155381}
	size := len(mustTestTx(t))
	fee, err := MinFee(size, params)
	if err != nil {
		t.Fatalf("MinFee: %v", err)
	}
	want := uint64(44)*uint64(size) + 155381
	if fee != want {
		t.Fatalf("MinFee = %d, want %d", fee, want)
	}
}

func TestMinFeeRejectsInvalidAndOverflowingInputs(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		params ProtocolParams
	}{
		{
			name:   "negative size",
			size:   -1,
			params: ProtocolParams{TxFeeFixed: 7},
		},
		{
			name:   "multiplication overflow",
			size:   2,
			params: ProtocolParams{TxFeePerByte: math.MaxUint64},
		},
		{
			name:   "addition overflow",
			size:   1,
			params: ProtocolParams{TxFeePerByte: math.MaxUint64, TxFeeFixed: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := MinFee(tt.size, tt.params); err == nil {
				t.Fatal("MinFee accepted invalid input")
			}
		})
	}
}

func TestMinFeeAcceptsProtocolCoinBoundaries(t *testing.T) {
	fee, err := MinFee(0, ProtocolParams{
		TxFeePerByte: math.MaxUint64,
		TxFeeFixed:   math.MaxUint64,
	})
	if err != nil {
		t.Fatalf("MinFee rejected valid zero-size boundary: %v", err)
	}
	if fee != math.MaxUint64 {
		t.Fatalf("MinFee = %d, want %d", fee, uint64(math.MaxUint64))
	}
}

func TestParseProtocolParams(t *testing.T) {
	p, err := ParseProtocolParams([]byte(`{"txFeePerByte":44,"txFeeFixed":155381,"extra":"ignored"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.TxFeePerByte != 44 || p.TxFeeFixed != 155381 {
		t.Fatalf("unexpected params: %+v", p)
	}
}

func TestParseProtocolParams_RequiresBothFeeFields(t *testing.T) {
	tests := []string{
		`{"txFeePerByte":44}`,
		`{"txFeeFixed":155381}`,
		`{}`,
	}
	for _, js := range tests {
		if _, err := ParseProtocolParams([]byte(js)); err == nil {
			t.Fatalf("expected error for params %s", js)
		}
	}
}

func TestParseProtocolParamsRejectsOutOfRangeJSON(t *testing.T) {
	tests := []string{
		`{"txFeePerByte":-1,"txFeeFixed":0}`,
		`{"txFeePerByte":18446744073709551616,"txFeeFixed":0}`,
		`{"txFeePerByte":0.5,"txFeeFixed":0}`,
	}
	for _, js := range tests {
		t.Run(js, func(t *testing.T) {
			if _, err := ParseProtocolParams([]byte(js)); err == nil {
				t.Fatal("expected protocol parameter range error")
			}
		})
	}
}

func TestParseProtocolParamsAcceptsProtocolCoinBoundaries(t *testing.T) {
	p, err := ParseProtocolParams([]byte(`{"txFeePerByte":18446744073709551615,"txFeeFixed":18446744073709551615}`))
	if err != nil {
		t.Fatalf("parse protocol Coin boundaries: %v", err)
	}
	if p.TxFeePerByte != math.MaxUint64 || p.TxFeeFixed != math.MaxUint64 {
		t.Fatalf("unexpected protocol params: %+v", p)
	}
}
