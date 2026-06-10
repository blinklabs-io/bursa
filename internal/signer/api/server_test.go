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
	"context"
	"crypto/ed25519"
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
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// minimal fake Cardano returning a fixed inspection/txid/assembled blob
type fakeCardano struct{ pub ed25519.PublicKey }

func (fakeCardano) Inspect([]byte) (*bursa.TxInspection, error) {
	return &bursa.TxInspection{TxId: "deadbeef", TTL: 1, Outputs: []bursa.TxOutput{{Address: "addr1ok", Lovelace: "1"}}}, nil
}
func (fakeCardano) TxID([]byte) ([]byte, error)                            { return make([]byte, 32), nil }
func (fakeCardano) Assemble([]byte, []lcommon.VkeyWitness) ([]byte, error) { return []byte{0x9}, nil }

func newTestServer(t *testing.T) (*Server, backend.KeyHash) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := backend.NewSoftwareBackend("software")
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, backend.KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	pol := policy.KeyPolicy{Hash: h.String(), AllowedRequests: []string{"tx"}, Tx: &policy.TxPolicy{}}
	eng, _ := policy.NewEngine([]policy.KeyPolicy{pol})
	coord := signer.New(signer.Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.Cardano(fakeCardano{pub: pub}),
	})
	return NewServer(coord, backend.NewResolver(b), func(string) (string, error) { return "tester", nil }), h
}

func TestHandleSignTx(t *testing.T) {
	srv, h := newTestServer(t)
	body, _ := json.Marshal(SignRequest{Type: "tx", Cbor: "83a0a0f5f6", Signers: []string{h.String()}})
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	req = req.WithContext(context.Background())
	rr := httptest.NewRecorder()
	srv.handleSign(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp SignTxResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Witnesses) != 1 || resp.TxID != "deadbeef" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHandleSign_BodyTooLarge(t *testing.T) {
	srv, _ := newTestServer(t)
	body := append([]byte(`{"type":"tx","cbor":"`), bytes.Repeat([]byte("a"), 1<<20)...)
	body = append(body, []byte(`"}`)...)
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleSign(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleListKeys(t *testing.T) {
	srv, h := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	srv.handleListKeys(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(h.String())) {
		t.Fatalf("expected key hash in listing")
	}
}

// TestMaskSignerErrors_PerEntry verifies that per-entry masking preserves
// 4xx reasons (denied, not_found) and replaces only 5xx reasons.
func TestMaskSignerErrors_PerEntry(t *testing.T) {
	input := []signer.SignerError{
		{Signer: "a", Code: signer.CodeDenied, Reason: "no policy configured for key a"},
		{Signer: "b", Code: signer.CodeBackend, Reason: "remote signing failed: connection refused"},
		{Signer: "c", Code: signer.CodeNotFound, Reason: "key not found"},
	}
	got := maskSignerErrors(input)
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	// CodeDenied (403) — reason must survive unmasked.
	if got[0].Reason != input[0].Reason {
		t.Errorf("denied reason should be preserved; got %q", got[0].Reason)
	}
	// CodeBackend (502) — reason must be replaced.
	if got[1].Reason != "backend error" {
		t.Errorf("backend reason should be masked to %q; got %q", "backend error", got[1].Reason)
	}
	// CodeNotFound (404) — reason must survive unmasked.
	if got[2].Reason != input[2].Reason {
		t.Errorf("not_found reason should be preserved; got %q", got[2].Reason)
	}
}

// TestHandleSignTx_DeniedReasonSurvives verifies that when all signers are
// denied (403) the denial reason appears unmasked in the response body.
// The test uses an unknown key hash (not registered in the backend) so the
// policy engine returns CodeNotFound → 404, which is a 4xx and must survive.
func TestHandleSignTx_DeniedReasonSurvives(t *testing.T) {
	srv, _ := newTestServer(t)

	// Generate a second key that exists in NO policy and is NOT registered in
	// the backend — coordinator returns CodeNotFound with reason "key not found".
	unknownPub, _, _ := ed25519.GenerateKey(nil)
	unknownHash := backend.HashPublicKey(unknownPub)

	body, _ := json.Marshal(SignRequest{
		Type:    "tx",
		Cbor:    "83a0a0f5f6",
		Signers: []string{unknownHash.String()},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	req = req.WithContext(context.Background())
	rr := httptest.NewRecorder()
	srv.handleSign(rr, req)

	// Expect 404 (CodeNotFound).
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp SignTxResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected at least one signer error in response")
	}
	// The not_found reason must NOT be masked to "backend error".
	if resp.Errors[0].Reason == "backend error" {
		t.Errorf("4xx (not_found) reason should not be masked; got %q", resp.Errors[0].Reason)
	}
	if resp.Errors[0].Reason == "" {
		t.Errorf("not_found reason should be non-empty")
	}
}

// TestHandleGetKey exercises GET /v1/keys/{hash} through the full Handler()
// so that PathValue is populated by Go's HTTP router.
func TestHandleGetKey(t *testing.T) {
	srv, h := newTestServer(t)
	handler := srv.Handler()

	t.Run("known hash returns 200 with correct JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/keys/"+h.String(), nil)
		req.Header.Set("Authorization", "Bearer x")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var info KeyInfo
		if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if info.Hash != h.String() {
			t.Errorf("expected hash %s, got %s", h.String(), info.Hash)
		}
	})

	t.Run("unknown valid-format hash returns 404", func(t *testing.T) {
		// All-zeros hash has valid format but is not registered.
		zeroHash := backend.KeyHash{}
		req := httptest.NewRequest(http.MethodGet, "/v1/keys/"+zeroHash.String(), nil)
		req.Header.Set("Authorization", "Bearer x")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}
