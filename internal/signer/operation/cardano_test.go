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

package operation

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/gouroboros/ledger"
)

// compile-time assertion that the real adapter satisfies the interface.
var _ Cardano = BursaCardano{}

func TestBursaCardano_TxID_BadInput(t *testing.T) {
	if _, err := (BursaCardano{}).TxID([]byte{0x00}, ledger.TxTypeConway); err == nil {
		t.Fatalf("expected error decoding garbage tx")
	}
}

func TestBursaCardano_Operations_BadInput(t *testing.T) {
	if _, err := (BursaCardano{}).Operations([]byte{0x00}, ledger.TxTypeConway); err == nil {
		t.Fatalf("expected error decoding garbage tx")
	}
}

// TestBursaCardano_Operations_RealTx decodes the Conway fixture (one pool
// registration certificate) and confirms the typed certificate kind surfaces.
func TestBursaCardano_Operations_RealTx(t *testing.T) {
	raw, err := os.ReadFile("../testdata/conway-unsigned.tx")
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	cbor, err := bursa.ReadCborInput(raw)
	if err != nil {
		t.Fatalf("ReadCborInput: %v", err)
	}
	ops, err := (BursaCardano{}).Operations(cbor, ledger.TxTypeConway)
	if err != nil {
		t.Fatalf("Operations: %v", err)
	}
	if len(ops.Certificates) != 1 || ops.Certificates[0] != policy.CertPoolRegistration {
		t.Fatalf("expected [pool_registration], got %v", ops.Certificates)
	}
}

// TestBursaCardano_DecodesGivenEra confirms Inspect, Operations and TxID decode
// with the era they are given rather than inferring one from the CBOR.
func TestBursaCardano_DecodesGivenEra(t *testing.T) {
	// Valid in the Alonzo, Babbage and Conway eras.
	ambiguous, err := hex.DecodeString("84a3008001800200a0f5f6")
	if err != nil {
		t.Fatal(err)
	}
	// Carries a Conway voting procedure, so it is not valid Babbage CBOR.
	conwayOnly, err := hex.DecodeString("84a400800180020013a18202581c00000000000000000000000000000000000000000000000000000000a18258200000000000000000000000000000000000000000000000000000000000000000008201f6a0f5f6")
	if err != nil {
		t.Fatal(err)
	}
	card := BursaCardano{}
	var firstID []byte
	for txType, want := range map[uint]string{
		ledger.TxTypeAlonzo:  "Alonzo",
		ledger.TxTypeBabbage: "Babbage",
		ledger.TxTypeConway:  "Conway",
	} {
		insp, err := card.Inspect(ambiguous, txType)
		if err != nil {
			t.Fatalf("Inspect(%s): %v", want, err)
		}
		if insp.Era != want {
			t.Errorf("Inspect era = %q, want %q", insp.Era, want)
		}
		id, err := card.TxID(ambiguous, txType)
		if err != nil {
			t.Fatalf("TxID(%s): %v", want, err)
		}
		if firstID == nil {
			firstID = id
		} else if !bytes.Equal(id, firstID) {
			t.Errorf("TxID(%s) = %x, want %x", want, id, firstID)
		}
	}
	if _, err := card.Inspect(conwayOnly, ledger.TxTypeBabbage); err == nil {
		t.Error("Inspect decoded Conway-only CBOR as Babbage")
	}
	if _, err := card.Operations(conwayOnly, ledger.TxTypeBabbage); err == nil {
		t.Error("Operations decoded Conway-only CBOR as Babbage")
	}
	if _, err := card.TxID(conwayOnly, ledger.TxTypeBabbage); err == nil {
		t.Error("TxID decoded Conway-only CBOR as Babbage")
	}
	ops, err := card.Operations(conwayOnly, ledger.TxTypeConway)
	if err != nil {
		t.Fatalf("Operations(Conway): %v", err)
	}
	if len(ops.Voters) != 1 {
		t.Errorf("Operations(Conway) voters = %d, want 1", len(ops.Voters))
	}
}
