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

import "testing"

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
	fee := MinFee(size, params)
	want := uint64(44)*uint64(size) + 155381
	if fee != want {
		t.Fatalf("MinFee = %d, want %d", fee, want)
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
