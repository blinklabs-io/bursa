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
	"os"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
)

// compile-time assertion that the real adapter satisfies the interface.
var _ Cardano = BursaCardano{}

func TestBursaCardano_TxID_BadInput(t *testing.T) {
	if _, err := (BursaCardano{}).TxID([]byte{0x00}); err == nil {
		t.Fatalf("expected error decoding garbage tx")
	}
}

func TestBursaCardano_Operations_BadInput(t *testing.T) {
	if _, err := (BursaCardano{}).Operations([]byte{0x00}); err == nil {
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
	ops, err := (BursaCardano{}).Operations(cbor)
	if err != nil {
		t.Fatalf("Operations: %v", err)
	}
	if len(ops.Certificates) != 1 || ops.Certificates[0] != policy.CertPoolRegistration {
		t.Fatalf("expected [pool_registration], got %v", ops.Certificates)
	}
}
