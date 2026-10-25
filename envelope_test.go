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
	"encoding/hex"
	"testing"

	"github.com/blinklabs-io/gouroboros/ledger"
)

func TestReadCborInput_Hex(t *testing.T) {
	raw := []byte{0x83, 0x01, 0x02, 0x03}
	got, err := ReadCborInput([]byte(hex.EncodeToString(raw)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(raw) {
		t.Fatalf("got %x want %x", got, raw)
	}
}

func TestReadCborInput_Envelope(t *testing.T) {
	raw := []byte{0x83, 0x01, 0x02, 0x03}
	env := []byte(`{"type":"Tx ConwayEra","description":"","cborHex":"83010203"}`)
	got, err := ReadCborInput(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(raw) {
		t.Fatalf("got %x want %x", got, raw)
	}
}

func TestEnvelopeTypeForEra(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		txType          uint
		wantTx, wantWit string
	}{
		{"shelley", ledger.TxTypeShelley, "TxSignedShelley", "TxWitness ShelleyEra"},
		{"allegra", ledger.TxTypeAllegra, "Tx AllegraEra", "TxWitness AllegraEra"},
		{"mary", ledger.TxTypeMary, "Tx MaryEra", "TxWitness MaryEra"},
		{"alonzo", ledger.TxTypeAlonzo, "Tx AlonzoEra", "TxWitness AlonzoEra"},
		{"babbage", ledger.TxTypeBabbage, "Tx BabbageEra", "TxWitness BabbageEra"},
		{"conway", ledger.TxTypeConway, "Tx ConwayEra", "TxWitness ConwayEra"},
		{"dijkstra", ledger.TxTypeDijkstra, "Tx DijkstraEra", "TxWitness DijkstraEra"},
		{"byron", ledger.TxTypeByron, "Tx", "TxWitness"},
		{"unknown", 999, "Tx", "TxWitness"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := txEnvelopeType(tc.txType); got != tc.wantTx {
				t.Errorf("txEnvelopeType = %q, want %q", got, tc.wantTx)
			}
			if got := txWitnessEnvelopeType(tc.txType); got != tc.wantWit {
				t.Errorf("txWitnessEnvelopeType = %q, want %q", got, tc.wantWit)
			}
		})
	}
}
