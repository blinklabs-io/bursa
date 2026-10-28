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

package confidentialspace

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

const testKMSKey = "projects/data/locations/global/keyRings/custody/cryptoKeys/pool"

type memoryStore struct {
	mu   sync.Mutex
	data []byte
}

func (s *memoryStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return nil, ErrEnvelopeNotFound
	}
	return append([]byte(nil), s.data...), nil
}

func (s *memoryStore) Create(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data != nil {
		return ErrEnvelopeExists
	}
	s.data = append([]byte(nil), data...)
	return nil
}

type testWrapper struct {
	denyWrap   bool
	denyUnwrap bool
}

func (w *testWrapper) Wrap(
	_ context.Context,
	plaintext, aad []byte,
) ([]byte, error) {
	if w.denyWrap {
		return nil, errors.New("KMS denied encrypt")
	}
	return testSeal(plaintext, aad), nil
}

func (w *testWrapper) Unwrap(
	_ context.Context,
	ciphertext, aad []byte,
) ([]byte, error) {
	if w.denyUnwrap {
		return nil, errors.New("KMS denied decrypt")
	}
	return testOpen(ciphertext, aad)
}

func testSeal(plaintext, aad []byte) []byte {
	key := sha256.Sum256([]byte("test key wrapper"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, aad)
}

func testOpen(ciphertext, aad []byte) ([]byte, error) {
	key := sha256.Sum256([]byte("test key wrapper"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("short ciphertext")
	}
	return gcm.Open(
		nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		aad,
	)
}

type testTokens struct {
	mu       sync.Mutex
	audience string
	nonces   []string
	err      error
}

func (s *testTokens) Token(
	_ context.Context,
	audience string,
	nonces []string,
) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audience = audience
	s.nonces = append([]string(nil), nonces...)
	if s.err != nil {
		return nil, s.err
	}
	return []byte("attestation-token"), nil
}

func newTestWorkload(
	t *testing.T,
	store *memoryStore,
	wrapper *testWrapper,
	tokens *testTokens,
) *Workload {
	t.Helper()
	w, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool",
		KMSKey:   testKMSKey,
		Tokens:   tokens,
		Wrapper:  wrapper,
		Store:    store,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func TestWorkloadInventorySignAndRestart(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	tokens := &testTokens{}
	wrapper := &testWrapper{}
	w := newTestWorkload(t, store, wrapper, tokens)

	nonce := bytes.Repeat([]byte{0x42}, 32)
	inv, err := w.Inventory(t.Context(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Keys) != 1 || inv.Keys[0].Role != backend.KeyTypePool ||
		!bytes.Equal(inv.Keys[0].PublicKey, w.pub) {
		t.Fatalf("inventory = %+v", inv.Keys)
	}
	if tokens.audience != "https://signer.example/pool" {
		t.Fatalf("audience = %q", tokens.audience)
	}
	wantBinding := hex.EncodeToString(backend.InventoryBinding(nonce, inv.Keys))
	if len(tokens.nonces) != 1 || tokens.nonces[0] != wantBinding {
		t.Fatalf("attestation nonces = %v, want %q", tokens.nonces, wantBinding)
	}

	kesVKey := bytes.Repeat([]byte{0x23}, 32)
	payload := lcommon.OpCertSignableBytes(kesVKey, 7, 11)
	req := backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: backend.PurposeOpCert,
		KeyHash: w.hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{0x24}, 32),
		Payload: payload,
	}
	resp, err := w.Sign(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error != "" || !ed25519.Verify(w.pub, payload, resp.Signature) {
		t.Fatalf("invalid opcert signature response: %+v", resp)
	}
	if err := ledger.VerifyOpCertSignature(&ledger.OpCert{
		KesVkey: kesVKey, IssueNumber: 7, KesPeriod: 11, ColdSignature: resp.Signature,
	}, w.pub); err != nil {
		t.Fatalf("canonical opcert verification: %v", err)
	}
	if replay, err := w.Sign(t.Context(), req); err != nil ||
		replay.Error == "" ||
		replay.Signature != nil {
		t.Fatalf("replay response = %+v, err = %v", replay, err)
	}

	firstPub := append([]byte(nil), w.pub...)
	seed := append([]byte(nil), w.priv[:ed25519.SeedSize]...)
	store.mu.Lock()
	stored := append([]byte(nil), store.data...)
	store.mu.Unlock()
	if bytes.Contains(stored, seed) || bytes.Contains(stored, w.priv) {
		t.Fatal("persisted envelope contains plaintext pool key material")
	}
	_ = w.Close()
	restarted := newTestWorkload(t, store, wrapper, &testTokens{})
	if !bytes.Equal(restarted.pub, firstPub) {
		t.Fatal("restart changed the pool cold public key")
	}
	req.KeyHash = restarted.hash.String()
	req.Nonce = bytes.Repeat([]byte{0x25}, 32)
	resp, err = restarted.Sign(t.Context(), req)
	if err != nil || !ed25519.Verify(restarted.pub, payload, resp.Signature) {
		t.Fatalf("restarted signature: response=%+v err=%v", resp, err)
	}
}

func TestWorkloadFailsClosed(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	w := newTestWorkload(t, store, &testWrapper{}, &testTokens{})
	payload := lcommon.OpCertSignableBytes(
		bytes.Repeat([]byte{0x23}, 32),
		7,
		11,
	)
	valid := backend.AttestedRequest{
		Version: backend.AttestedProtocol,
		Purpose: backend.PurposeOpCert,
		KeyHash: w.hash.String(),
		Role:    backend.KeyTypePool,
		Nonce:   bytes.Repeat([]byte{0x24}, 32),
		Payload: payload,
	}
	for name, mutate := range map[string]func(*backend.AttestedRequest){
		"version":  func(r *backend.AttestedRequest) { r.Version = "other" },
		"purpose":  func(r *backend.AttestedRequest) { r.Purpose = backend.PurposeTxHash },
		"key hash": func(r *backend.AttestedRequest) { r.KeyHash = backend.KeyHash{}.String() },
		"role":     func(r *backend.AttestedRequest) { r.Role = backend.KeyTypePayment },
		"nonce":    func(r *backend.AttestedRequest) { r.Nonce = []byte("short") },
		"payload":  func(r *backend.AttestedRequest) { r.Payload = r.Payload[:47] },
	} {
		t.Run(name, func(t *testing.T) {
			req := valid
			req.Nonce = append([]byte(nil), valid.Nonce...)
			req.Payload = append([]byte(nil), valid.Payload...)
			mutate(&req)
			resp, err := w.Sign(t.Context(), req)
			if err != nil || resp.Error == "" || resp.Signature != nil {
				t.Fatalf("response=%+v err=%v", resp, err)
			}
		})
	}

	_, wrong, _ := ed25519.GenerateKey(nil)
	w.signFunc = func(ed25519.PrivateKey, []byte) []byte { return ed25519.Sign(wrong, valid.Payload) }
	valid.Nonce = bytes.Repeat([]byte{0x99}, 32)
	if resp, err := w.Sign(t.Context(), valid); err == nil ||
		resp.Signature != nil {
		t.Fatalf("mismatched signature response=%+v err=%v", resp, err)
	}
}

func TestWorkloadKMSDenialAndMissingAttestation(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	w := newTestWorkload(t, store, &testWrapper{}, &testTokens{})
	_ = w.Close()
	_, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool", KMSKey: testKMSKey,
		Tokens: &testTokens{}, Wrapper: &testWrapper{denyUnwrap: true}, Store: store,
	})
	if err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("KMS denied decrypt")) {
		t.Fatalf("KMS denial error = %v", err)
	}

	attestationDown := newTestWorkload(
		t,
		&memoryStore{},
		&testWrapper{},
		&testTokens{err: errors.New("no attestation")},
	)
	if _, err := attestationDown.Inventory(t.Context(), make([]byte, 32)); err == nil {
		t.Fatal("inventory succeeded without attestation")
	}
}

type acceptEvidence struct{}

func (acceptEvidence) Verify(
	context.Context,
	[]byte,
	[]byte,
) error {
	return nil
}

func TestWorkloadExistingAttestedContract(t *testing.T) {
	t.Parallel()
	w := newTestWorkload(t, &memoryStore{}, &testWrapper{}, &testTokens{})
	srv := httptest.NewServer(w.Handler())
	t.Cleanup(srv.Close)
	enclave, err := backend.NewHTTPEnclave(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b := backend.NewAttestedBackend("gcp", enclave, acceptEvidence{})
	if err := b.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ref, err := b.GetKey(t.Context(), w.hash)
	if err != nil {
		t.Fatal(err)
	}
	payload := lcommon.OpCertSignableBytes(make([]byte, 32), 2, 3)
	sig, err := backend.SignFor(
		t.Context(),
		ref,
		backend.PurposeOpCert,
		payload,
	)
	if err != nil || !ed25519.Verify(ref.PublicKey(), payload, sig) {
		t.Fatalf("sign error=%v", err)
	}
}

func TestWorkloadHandlerRejectsMalformedRequests(t *testing.T) {
	t.Parallel()
	w := newTestWorkload(t, &memoryStore{}, &testWrapper{}, &testTokens{})
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
	}{
		{"wrong content type", "text/plain", `{}`},
		{"unknown field", "application/json", `{"nonce":"","extra":true}`},
		{"trailing JSON", "application/json", `{"nonce":""}{}`},
		{"oversized", "application/json", strings.Repeat(" ", maxRequestBody+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPost,
				"/v1/inventory",
				strings.NewReader(tc.body),
			)
			req.Header.Set("Content-Type", tc.contentType)
			rw := httptest.NewRecorder()
			w.Handler().ServeHTTP(rw, req)
			if rw.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rw.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestWrappedEnvelopeRejectsTampering(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	w := newTestWorkload(t, store, &testWrapper{}, &testTokens{})
	_ = w.Close()
	store.mu.Lock()
	var e envelope
	if err := json.Unmarshal(store.data, &e); err != nil {
		t.Fatal(err)
	}
	e.PublicKey[0] ^= 1
	store.data, _ = json.Marshal(e)
	store.mu.Unlock()
	_, err := New(t.Context(), Config{
		Audience: "https://signer.example/pool", KMSKey: testKMSKey,
		Tokens: &testTokens{}, Wrapper: &testWrapper{}, Store: store,
	})
	if err == nil {
		t.Fatal("tampered envelope loaded")
	}
}
