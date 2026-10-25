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
	"errors"
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

func TestEnvelopeTxType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		envType      string
		wantType     uint
		wantDeclared bool
		wantErr      bool
	}{
		{"", 0, false, false},
		{"Tx", 0, false, false},
		{"Tx BabbageEra", ledger.TxTypeBabbage, true, false},
		{"Unwitnessed Tx BabbageEra", ledger.TxTypeBabbage, true, false},
		{"Witnessed Tx AlonzoEra", ledger.TxTypeAlonzo, true, false},
		{"Tx ConwayEra", ledger.TxTypeConway, true, false},
		{"TxSignedShelley", ledger.TxTypeShelley, true, false},
		{"TxUnsignedShelley", ledger.TxTypeShelley, true, false},
		{"Tx GoguenEra", 0, false, true},
		{"Tx Babbage", 0, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.envType, func(t *testing.T) {
			t.Parallel()
			got, declared, err := envelopeTxType(tc.envType)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.wantType || declared != tc.wantDeclared {
				t.Errorf("got (%d, %v), want (%d, %v)", got, declared, tc.wantType, tc.wantDeclared)
			}
		})
	}
}

func TestReadTxInput(t *testing.T) {
	t.Parallel()
	const babbageHex = "84a3008001800200a0f5f6"
	envelope := func(envType, cborHex string) string {
		return `{"type":"` + envType + `","description":"","cborHex":"` + cborHex + `"}`
	}
	conwayHex := hex.EncodeToString(mustTestTx(t))
	tests := []struct {
		name      string
		input     string
		era       string
		wantType  uint
		ambiguous bool
		wantErr   bool
	}{
		{"babbage envelope", envelope("Tx BabbageEra", babbageHex), "", ledger.TxTypeBabbage, false, false},
		{"babbage raw hex", babbageHex, "", 0, true, true},
		{"babbage legacy Tx envelope", envelope("Tx", babbageHex), "", 0, true, true},
		{"babbage raw hex with era", babbageHex, "babbage", ledger.TxTypeBabbage, false, false},
		{"era conflicts with envelope", envelope("Tx BabbageEra", babbageHex), "conway", 0, false, true},
		{"conway raw hex", conwayHex, "", ledger.TxTypeConway, false, false},
		{"conway legacy Tx envelope", envelope("Tx", conwayHex), "", ledger.TxTypeConway, false, false},
		{"conway CBOR in babbage envelope", envelope("Tx BabbageEra", conwayHex), "", 0, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, got, err := ReadTxInput([]byte(tc.input), tc.era)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if errors.Is(err, ErrAmbiguousTxEra) != tc.ambiguous {
				t.Fatalf("err = %v, want ErrAmbiguousTxEra: %v", err, tc.ambiguous)
			}
			if err != nil {
				return
			}
			if got != tc.wantType {
				t.Errorf("tx type = %d, want %d", got, tc.wantType)
			}
			if len(raw) == 0 {
				t.Errorf("empty CBOR")
			}
		})
	}
}
