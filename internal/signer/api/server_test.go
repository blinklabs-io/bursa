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
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/prometheus/client_golang/prometheus"
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
	return NewServer(coord, backend.NewResolver(b), eng, nil, func(string) (string, error) { return "tester", nil }), h
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

// newOpCertServer builds a server whose cold key allows the given request
// types. It returns the server, the cold key hash, and the cold public key so
// tests can verify produced signatures.
func newOpCertServer(t *testing.T, allowedRequests []string, acl *CallerACL) (*Server, backend.KeyHash, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := backend.NewSoftwareBackend("software")
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, backend.KeyTypePool)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	pol := policy.KeyPolicy{Hash: h.String(), AllowedRequests: allowedRequests}
	eng, err := policy.NewEngine([]policy.KeyPolicy{pol})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	coord := signer.New(signer.Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.Cardano(fakeCardano{pub: pub}),
	})
	srv := NewServer(coord, backend.NewResolver(b), eng, acl, func(string) (string, error) { return "tester", nil })
	return srv, h, pub
}

// TestHandleSignOpCert_Valid verifies a cold-sign request returns a signature
// that verifies against the KES vkey/counter/period with the cold public key.
func TestHandleSignOpCert_Valid(t *testing.T) {
	srv, h, coldPub := newOpCertServer(t, []string{"opcert"}, nil)

	kesVkey := bytes.Repeat([]byte{0xAB}, 32)
	const issueCounter = uint64(7)
	const kesPeriod = uint64(42)

	body, _ := json.Marshal(SignRequest{
		Type:         "opcert",
		Key:          h.String(),
		KesVkey:      hex.EncodeToString(kesVkey),
		IssueCounter: issueCounter,
		KesPeriod:    kesPeriod,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	req = req.WithContext(context.Background())
	rr := httptest.NewRecorder()
	srv.handleSign(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp SignOpCertResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Key != h.String() {
		t.Errorf("expected key %s, got %s", h.String(), resp.Key)
	}
	if resp.ColdVkey != hex.EncodeToString(coldPub) {
		t.Errorf("cold_vkey mismatch: got %s", resp.ColdVkey)
	}
	sig, err := hex.DecodeString(resp.Signature)
	if err != nil {
		t.Fatalf("signature not hex: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte signature, got %d", ed25519.SignatureSize, len(sig))
	}
	// The signature must verify over the canonical OCertSignable bytes.
	signable := lcommon.OpCertSignableBytes(kesVkey, issueCounter, kesPeriod)
	if !ed25519.Verify(coldPub, signable, sig) {
		t.Fatal("cold-key signature failed to verify over OCertSignable bytes")
	}
	// A signature over different opcert parameters must NOT verify (guards
	// against signing the wrong payload).
	wrong := lcommon.OpCertSignableBytes(kesVkey, issueCounter+1, kesPeriod)
	if ed25519.Verify(coldPub, wrong, sig) {
		t.Fatal("signature unexpectedly verified over mismatched parameters")
	}
}

// TestHandleSignOpCert_MalformedInput rejects bad KES vkey hex and wrong-length
// KES vkeys with 400.
func TestHandleSignOpCert_MalformedInput(t *testing.T) {
	srv, h, _ := newOpCertServer(t, []string{"opcert"}, nil)

	t.Run("non-hex kes_vkey", func(t *testing.T) {
		body, _ := json.Marshal(SignRequest{Type: "opcert", Key: h.String(), KesVkey: "zzzz"})
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		srv.handleSign(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("wrong-length kes_vkey", func(t *testing.T) {
		body, _ := json.Marshal(SignRequest{
			Type:    "opcert",
			Key:     h.String(),
			KesVkey: hex.EncodeToString(bytes.Repeat([]byte{0x01}, 16)),
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		srv.handleSign(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for short KES vkey, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid key id", func(t *testing.T) {
		body, _ := json.Marshal(SignRequest{
			Type:    "opcert",
			Key:     "nothex",
			KesVkey: hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		srv.handleSign(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid key id, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestHandleSignOpCert_PolicyDenied verifies deny-by-default: a cold key whose
// policy does not list "opcert" cannot cold-sign (403).
func TestHandleSignOpCert_PolicyDenied(t *testing.T) {
	// Key allows only "tx", not "opcert".
	srv, h, _ := newOpCertServer(t, []string{"tx"}, nil)

	body, _ := json.Marshal(SignRequest{
		Type:    "opcert",
		Key:     h.String(),
		KesVkey: hex.EncodeToString(bytes.Repeat([]byte{0x02}, 32)),
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleSign(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for policy denial, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleSignOpCert_ACLDenied verifies the caller ACL gates opcert exactly
// like the other sign types: an unlisted caller gets 403.
func TestHandleSignOpCert_ACLDenied(t *testing.T) {
	// Build with a placeholder ACL, then rebuild with an ACL keyed on the real
	// cold key hash.
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := backend.NewSoftwareBackend("software")
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, backend.KeyTypePool)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	pol := policy.KeyPolicy{Hash: h.String(), AllowedRequests: []string{"opcert"}}
	eng, _ := policy.NewEngine([]policy.KeyPolicy{pol})
	coord := signer.New(signer.Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.Cardano(fakeCardano{pub: pub}),
	})
	acl := NewCallerACL(map[string][]backend.KeyHash{"alice": {h}})
	srv := NewServer(coord, backend.NewResolver(b), eng, acl, func(string) (string, error) { return "tester", nil })

	body, _ := json.Marshal(SignRequest{
		Type:    "opcert",
		Key:     h.String(),
		KesVkey: hex.EncodeToString(bytes.Repeat([]byte{0x03}, 32)),
	})

	t.Run("bob denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		req = withCaller(req, "bob")
		rr := httptest.NewRecorder()
		srv.handleSign(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for bob, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("alice allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		req = withCaller(req, "alice")
		rr := httptest.NewRecorder()
		srv.handleSign(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for alice, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// withCaller returns a copy of r with the given caller subject injected into
// its context (mimics what JWTMiddleware does).
func withCaller(r *http.Request, subject string) *http.Request {
	ctx := context.WithValue(r.Context(), callerKey, subject)
	return r.WithContext(ctx)
}

// gatherDenyACL gathers the current bursa_signer_deny_total{reason="acl"}
// sample value from g.
func gatherDenyACL(t *testing.T, g prometheus.Gatherer) float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "bursa_signer_deny_total" {
			continue
		}
		for _, mm := range mf.GetMetric() {
			for _, lp := range mm.GetLabel() {
				if lp.GetName() == "reason" && lp.GetValue() == "acl" {
					return mm.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// TestCallerACLEnforcement verifies per-caller key scoping (design §12).
func TestCallerACLEnforcement(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := backend.NewSoftwareBackend("software")
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, backend.KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	pol := policy.KeyPolicy{Hash: h.String(), AllowedRequests: []string{"tx", "cip8"}, Tx: &policy.TxPolicy{}, CIP8: &policy.CIP8Policy{}}
	eng, _ := policy.NewEngine([]policy.KeyPolicy{pol})
	coord := signer.New(signer.Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.Cardano(fakeCardano{pub: pub}),
	})

	// Register metrics once into a dedicated registry for all sub-tests.
	metricsReg := prometheus.NewRegistry()
	coord.Metrics().Register(metricsReg)

	// ACL: only "alice" may use the test key; "bob" is unlisted.
	acl := NewCallerACL(map[string][]backend.KeyHash{"alice": {h}})
	srv := NewServer(coord, backend.NewResolver(b), eng, acl, func(string) (string, error) { return "tester", nil })

	t.Run("bob: sign tx returns 403 with denied signer error and increments deny_total", func(t *testing.T) {
		before := gatherDenyACL(t, metricsReg)
		body, _ := json.Marshal(SignRequest{Type: "tx", Cbor: "83a0a0f5f6", Signers: []string{h.String()}})
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		req = withCaller(req, "bob")
		rr := httptest.NewRecorder()
		srv.handleSign(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for bob, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp SignTxResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Errors) == 0 || resp.Errors[0].Code != signer.CodeDenied {
			t.Fatalf("expected denied signer error, got %+v", resp.Errors)
		}
		after := gatherDenyACL(t, metricsReg)
		if delta := after - before; delta != 1 {
			t.Fatalf("expected deny_total{reason=acl} to increase by 1, got delta %v", delta)
		}
	})

	t.Run("bob: cip8 sign returns 403 and increments deny_total", func(t *testing.T) {
		before := gatherDenyACL(t, metricsReg)
		body, _ := json.Marshal(SignRequest{
			Type:    "cip8",
			Payload: "abcd",
			Address: "addr1q8gg9j5vkzsgz4dz3gfr4kz0f2nwzrqq0yfktqmwwpmaprkl43c7c4d9rg9rmk6z03rl4xt9gjtywtx0m09flxmqzq46ugh",
			Key:     h.String(),
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
		req = withCaller(req, "bob")
		rr := httptest.NewRecorder()
		srv.handleSign(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for bob cip8, got %d: %s", rr.Code, rr.Body.String())
		}
		after := gatherDenyACL(t, metricsReg)
		if delta := after - before; delta != 1 {
			t.Fatalf("expected deny_total{reason=acl} to increase by 1, got delta %v", delta)
		}
	})

	t.Run("bob: list keys returns empty list (view filter, not counted)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
		req = withCaller(req, "bob")
		rr := httptest.NewRecorder()
		srv.handleListKeys(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var keys []KeyInfo
		if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(keys) != 0 {
			t.Fatalf("expected empty key list for bob, got %d keys", len(keys))
		}
	})

	t.Run("bob: get key by hash returns 404 (no existence oracle)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/keys/"+h.String(), nil)
		req.SetPathValue("hash", h.String())
		req = withCaller(req, "bob")
		rr := httptest.NewRecorder()
		srv.handleGetKey(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for bob on key detail, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("alice: list keys returns the key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
		req = withCaller(req, "alice")
		rr := httptest.NewRecorder()
		srv.handleListKeys(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var keys []KeyInfo
		if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(keys) != 1 || keys[0].Hash != h.String() {
			t.Fatalf("expected alice to see test key, got %+v", keys)
		}
	})

	t.Run("alice: get key by hash returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/keys/"+h.String(), nil)
		req.SetPathValue("hash", h.String())
		req = withCaller(req, "alice")
		rr := httptest.NewRecorder()
		srv.handleGetKey(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for alice on key detail, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestCallerACL_PartialAllow verifies that a request with two signers — one
// ACL-allowed (signed successfully) and one ACL-denied — returns 200 with one
// witness and one error entry with code "denied".
func TestCallerACL_PartialAllow(t *testing.T) {
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

	// Second signer: valid 56-hex key hash that is not in the backend and not
	// ACL-allowed for "alice". Any all-zero-ish unique hash works.
	var deniedHash backend.KeyHash
	deniedHash[0] = 0xde
	deniedHash[1] = 0xad

	// ACL: alice may use h but NOT deniedHash.
	acl := NewCallerACL(map[string][]backend.KeyHash{"alice": {h}})
	srv := NewServer(coord, backend.NewResolver(b), eng, acl, func(string) (string, error) { return "tester", nil })

	body, _ := json.Marshal(SignRequest{
		Type:    "tx",
		Cbor:    "83a0a0f5f6",
		Signers: []string{h.String(), deniedHash.String()},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	req = withCaller(req, "alice")
	rr := httptest.NewRecorder()
	srv.handleSign(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for partial allow, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp SignTxResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Witnesses) != 1 {
		t.Fatalf("expected exactly 1 witness for the allowed signer, got %d", len(resp.Witnesses))
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("expected exactly 1 error for the denied signer, got %d: %+v", len(resp.Errors), resp.Errors)
	}
	if resp.Errors[0].Code != signer.CodeDenied {
		t.Fatalf("expected denied error code, got %q: %+v", resp.Errors[0].Code, resp.Errors[0])
	}
	if resp.Errors[0].Reason != "caller is not authorized for this key" {
		t.Fatalf("unexpected deny reason: %q", resp.Errors[0].Reason)
	}
}

// TestSignTx_StatusFromCoordinatorNotACL verifies that when a tx fully fails
// with a mix of an ACL pre-filter denial (always 403) and a coordinator
// per-signer error, the HTTP status reflects the coordinator error rather than
// the ACL denial. Prepending the ACL denial used to mask, e.g., a 404 as a 403.
func TestSignTx_StatusFromCoordinatorNotACL(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := backend.NewSoftwareBackend("software")
	if _, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, backend.KeyTypePayment); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	eng, _ := policy.NewEngine(nil)
	coord := signer.New(signer.Deps{
		Resolver:  backend.NewResolver(b),
		Policy:    eng,
		Watermark: watermark.NewMemWatermark(),
		Cardano:   operation.Cardano(fakeCardano{pub: pub}),
	})

	// allowedMissing: ACL-allowed for "alice" but absent from the backend, so the
	// coordinator returns not_found (404). deniedHash: not ACL-allowed (403).
	var allowedMissing backend.KeyHash
	allowedMissing[0] = 0xa1
	var deniedHash backend.KeyHash
	deniedHash[0] = 0xde
	deniedHash[1] = 0xad

	acl := NewCallerACL(map[string][]backend.KeyHash{"alice": {allowedMissing}})
	srv := NewServer(coord, backend.NewResolver(b), eng, acl, func(string) (string, error) { return "tester", nil })

	body, _ := json.Marshal(SignRequest{
		Type:    "tx",
		Cbor:    "83a0a0f5f6",
		Signers: []string{allowedMissing.String(), deniedHash.String()},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	req = withCaller(req, "alice")
	rr := httptest.NewRecorder()
	srv.handleSign(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 from coordinator not_found, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp SignTxResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Both failures must still be reported in the body.
	var sawDenied, sawNotFound bool
	for _, e := range resp.Errors {
		switch e.Code {
		case signer.CodeDenied:
			sawDenied = true
		case signer.CodeNotFound:
			sawNotFound = true
		}
	}
	if !sawDenied || !sawNotFound {
		t.Fatalf("expected both denied and not_found errors in body, got %+v", resp.Errors)
	}
}

// TestGetKey_PolicySummary verifies that GET /v1/keys/{hash} includes the
// effective policy when a policy entry exists, and omits it (null/absent) when
// the engine has no entry for the key (deny-by-default, design §8 + §10).
func TestGetKey_PolicySummary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := backend.NewSoftwareBackend("software")
	h, err := b.AddKey(&bursa.LoadedKey{SKey: []byte(priv), VKey: pub}, backend.KeyTypePayment)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	t.Run("key with policy returns policy summary", func(t *testing.T) {
		eng, err := policy.NewEngine([]policy.KeyPolicy{{
			Hash:            h.String(),
			AllowedRequests: []string{"tx"},
			Tx:              &policy.TxPolicy{MaxOutputAda: 5000},
		}})
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		coord := signer.New(signer.Deps{
			Resolver:  backend.NewResolver(b),
			Policy:    eng,
			Watermark: watermark.NewMemWatermark(),
			Cardano:   operation.Cardano(fakeCardano{pub: pub}),
		})
		srv := NewServer(coord, backend.NewResolver(b), eng, nil, func(string) (string, error) { return "tester", nil })
		handler := srv.Handler()

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
		if info.Policy == nil {
			t.Fatal("expected non-nil policy summary")
		}
		if len(info.Policy.AllowedRequests) != 1 || info.Policy.AllowedRequests[0] != "tx" {
			t.Errorf("expected AllowedRequests=[tx], got %v", info.Policy.AllowedRequests)
		}
		if info.Policy.Tx == nil {
			t.Fatal("expected non-nil Tx policy")
		}
		if info.Policy.Tx.MaxOutputAda != 5000 {
			t.Errorf("expected MaxOutputAda=5000, got %d", info.Policy.Tx.MaxOutputAda)
		}
		if info.Policy.CIP8 != nil {
			t.Errorf("expected nil CIP8 policy, got %+v", info.Policy.CIP8)
		}
	})

	t.Run("key without policy entry returns null policy (deny-by-default)", func(t *testing.T) {
		// Engine has no entry for h — deny-by-default.
		eng, err := policy.NewEngine([]policy.KeyPolicy{})
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		coord := signer.New(signer.Deps{
			Resolver:  backend.NewResolver(b),
			Policy:    eng,
			Watermark: watermark.NewMemWatermark(),
			Cardano:   operation.Cardano(fakeCardano{pub: pub}),
		})
		srv := NewServer(coord, backend.NewResolver(b), eng, nil, func(string) (string, error) { return "tester", nil })
		handler := srv.Handler()

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
		if info.Policy != nil {
			t.Errorf("expected nil policy for key with no policy entry, got %+v", info.Policy)
		}
	})
}
