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

package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/operation"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

const ambiguousBabbageTxHex = "84a3008001800200a0f5f6"

func newEraTestServer(t *testing.T) (*Server, backend.KeyHash) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b := backend.NewSoftwareBackend("software")
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, backend.KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            h.String(),
		AllowedRequests: []string{"tx"},
		Tx:              &policy.TxPolicy{},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	coord := signer.New(signer.Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.BursaCardano{},
	})
	return NewServer(coord, backend.NewResolver(b), eng, nil, nil), h
}

func postEraSignRequest(t *testing.T, srv *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.handleSign(rr, req)
	return rr
}

func TestHandleSignTxUsesRequestedEra(t *testing.T) {
	tests := []struct {
		name string
		cbor string
		era  string
	}{
		{
			name: "explicit era",
			cbor: ambiguousBabbageTxHex,
			era:  "babbage",
		},
		{
			name: "era typed envelope",
			cbor: `{"type":"Tx BabbageEra","description":"","cborHex":"` + ambiguousBabbageTxHex + `"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, h := newEraTestServer(t)
			request := map[string]any{
				"type":    "tx",
				"cbor":    tt.cbor,
				"signers": []string{h.String()},
			}
			if tt.era != "" {
				request["era"] = tt.era
			}
			rr := postEraSignRequest(t, srv, request)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
			}
			var resp SignTxResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			wits := make([]lcommon.VkeyWitness, 0, len(resp.Witnesses))
			for _, witHex := range resp.Witnesses {
				raw, err := hex.DecodeString(witHex)
				if err != nil {
					t.Fatalf("decode witness hex: %v", err)
				}
				wit, err := bursa.DecodeWitness(raw)
				if err != nil {
					t.Fatalf("DecodeWitness: %v", err)
				}
				wits = append(wits, wit)
			}
			unsigned, err := hex.DecodeString(ambiguousBabbageTxHex)
			if err != nil {
				t.Fatalf("decode unsigned tx: %v", err)
			}
			want, err := bursa.AssembleTransactionForEra(unsigned, ledger.TxTypeBabbage, wits)
			if err != nil {
				t.Fatalf("AssembleTransactionForEra: %v", err)
			}
			got, err := hex.DecodeString(resp.SignedTx)
			if err != nil {
				t.Fatalf("decode signed tx: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("signed tx uses the wrong era encoding:\n got %x\nwant %x", got, want)
			}
		})
	}
}

func TestHandleSignTxRejectsAmbiguousEra(t *testing.T) {
	srv, h := newEraTestServer(t)
	rr := postEraSignRequest(t, srv, map[string]any{
		"type":    "tx",
		"cbor":    ambiguousBabbageTxHex,
		"signers": []string{h.String()},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("transaction era is ambiguous")) {
		t.Fatalf("error = %s, want ambiguous-era rejection", rr.Body.String())
	}
}
