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

package signer

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/operation"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/blinklabs-io/gouroboros/ledger"
)

func TestIntegration_SignRealTx(t *testing.T) {
	raw, err := os.ReadFile("testdata/conway-unsigned.tx")
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	cbor, err := bursa.ReadCborInput(raw)
	if err != nil {
		t.Fatalf("ReadCborInput: %v", err)
	}

	pub, priv, _ := ed25519.GenerateKey(nil)
	b := backend.NewSoftwareBackend("software")
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv)}, backend.KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	// The fixture is a Conway tx with 1 certificate; AllowCertificates must be
	// true or the permissive policy would still deny the request.
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            h.String(),
		AllowedRequests: []string{"tx"},
		Tx: &policy.TxPolicy{
			AllowCertificates: true,
		},
	}})
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	c := New(Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.BursaCardano{},
	})

	res, perr, err := c.SignTx(context.Background(), []byte(hex.EncodeToString(cbor)), []string{h.String()})
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if len(perr) != 0 {
		t.Fatalf("per-signer errors: %+v", perr)
	}
	if len(res.SignedTx) == 0 {
		t.Fatalf("no signed tx produced")
	}

	// The assembled tx must decode and carry our witness, with the body (txid) unchanged.
	txType, err := ledger.DetermineTransactionType(res.SignedTx)
	if err != nil {
		t.Fatalf("DetermineTransactionType: %v", err)
	}
	signed, err := ledger.NewTransactionFromCbor(txType, res.SignedTx)
	if err != nil {
		t.Fatalf("decode signed tx: %v", err)
	}
	if signed.Hash().String() != res.TxID {
		t.Fatalf("txid changed: %s != %s", signed.Hash().String(), res.TxID)
	}
	txidBytes, err := hex.DecodeString(res.TxID)
	if err != nil {
		t.Fatalf("decode txid hex: %v", err)
	}
	found := false
	witnesses := signed.Witnesses()
	if witnesses == nil {
		t.Fatalf("signed transaction has no witnesses")
	}
	for _, w := range witnesses.Vkey() {
		if hex.EncodeToString(w.Vkey) == hex.EncodeToString(pub) {
			found = true
			if !ed25519.Verify(ed25519.PublicKey(w.Vkey), txidBytes, w.Signature) {
				t.Fatalf("witness signature does not verify against txid")
			}
		}
	}
	if !found {
		t.Fatalf("our vkey witness not present in assembled tx")
	}
}
