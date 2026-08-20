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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// signReq builds a request with authorized-keys signature headers for the given
// signing key, body, timestamp, and nonce.
func signReq(t *testing.T, caller string, priv ed25519.PrivateKey, method, path string, body []byte, ts time.Time, nonce string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	bodyHash := sha256.Sum256(body)
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	canonical := strings.Join([]string{method, path, hex.EncodeToString(bodyHash[:]), tsStr, nonce}, "|")
	sig := ed25519.Sign(priv, []byte(canonical))
	req.Header.Set(HeaderKey, caller)
	req.Header.Set(HeaderTimestamp, tsStr)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, hex.EncodeToString(sig))
	return req
}

func newAuth(t *testing.T) (*RequestSigningAuthenticator, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := NewRequestSigningAuthenticator(map[string]ed25519.PublicKey{"alice": pub}, 60*time.Second)
	return a, "alice", priv
}

func TestRequestSigning_Valid(t *testing.T) {
	a, caller, priv := newAuth(t)
	req := signReq(t, caller, priv, http.MethodPost, "/v1/sign", []byte(`{"type":"tx"}`), time.Now(), "n1")
	got, ok, err := a.Authenticate(req)
	if !ok || err != nil {
		t.Fatalf("valid request: ok=%v err=%v", ok, err)
	}
	if got != "alice" {
		t.Fatalf("caller = %q, want alice", got)
	}
	// Body must still be readable by downstream handlers.
	buf := make([]byte, 64)
	n, _ := req.Body.Read(buf)
	if string(buf[:n]) != `{"type":"tx"}` {
		t.Fatalf("body not preserved for handler: %q", buf[:n])
	}
}

func TestRequestSigning_NoHeaders_FallsThrough(t *testing.T) {
	a, _, _ := newAuth(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	caller, ok, err := a.Authenticate(req)
	if ok || err != nil || caller != "" {
		t.Fatalf("expected fall-through, got caller=%q ok=%v err=%v", caller, ok, err)
	}
}

func TestRequestSigning_BadSignature(t *testing.T) {
	a, caller, priv := newAuth(t)
	// Valid signature over nonce "n1", then submit it with nonce "n2": the
	// server rebuilds the canonical string with "n2", so verification fails.
	valid := signReq(t, caller, priv, http.MethodPost, "/v1/sign", []byte("body"), time.Now(), "n1")
	req := signReq(t, caller, priv, http.MethodPost, "/v1/sign", []byte("body"), time.Now(), "n2")
	req.Header.Set(HeaderSignature, valid.Header.Get(HeaderSignature))
	if _, ok, err := a.Authenticate(req); !ok || err == nil {
		t.Fatalf("bad signature should reject: ok=%v err=%v", ok, err)
	}
}

func TestRequestSigning_StaleTimestamp(t *testing.T) {
	a, caller, priv := newAuth(t)
	req := signReq(t, caller, priv, http.MethodPost, "/v1/sign", []byte("x"), time.Now().Add(-5*time.Minute), "n1")
	_, ok, err := a.Authenticate(req)
	if !ok || err == nil {
		t.Fatalf("stale timestamp should reject: ok=%v err=%v", ok, err)
	}
}

func TestRequestSigning_ReplayNonce(t *testing.T) {
	a, caller, priv := newAuth(t)
	body := []byte("replay-body")
	ts := time.Now()
	req1 := signReq(t, caller, priv, http.MethodPost, "/v1/sign", body, ts, "dup")
	if _, ok, err := a.Authenticate(req1); !ok || err != nil {
		t.Fatalf("first use should pass: ok=%v err=%v", ok, err)
	}
	// Replay the identical signed request (fresh reader, same headers).
	req2 := signReq(t, caller, priv, http.MethodPost, "/v1/sign", body, ts, "dup")
	if _, ok, err := a.Authenticate(req2); !ok || err == nil {
		t.Fatalf("replayed nonce should reject: ok=%v err=%v", ok, err)
	}
}

func TestRequestSigning_UnknownKey(t *testing.T) {
	a, _, priv := newAuth(t)
	req := signReq(t, "mallory", priv, http.MethodPost, "/v1/sign", []byte("x"), time.Now(), "n1")
	_, ok, err := a.Authenticate(req)
	if !ok || err == nil {
		t.Fatalf("unknown key should reject: ok=%v err=%v", ok, err)
	}
}

func TestRequestSigning_MissingHeaders(t *testing.T) {
	a, caller, priv := newAuth(t)
	req := signReq(t, caller, priv, http.MethodPost, "/v1/sign", []byte("x"), time.Now(), "n1")
	req.Header.Del(HeaderNonce) // signature present, nonce missing
	if _, ok, err := a.Authenticate(req); !ok || err == nil {
		t.Fatalf("missing nonce should reject: ok=%v err=%v", ok, err)
	}
}

// TestRequestSigning_ThroughMiddleware confirms the caller lands in context so
// the handler (and thus the ACL) sees it.
func TestRequestSigning_ThroughMiddleware(t *testing.T) {
	a, caller, priv := newAuth(t)
	var got string
	h := AuthMiddleware([]Authenticator{a}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = CallerFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := signReq(t, caller, priv, http.MethodPost, "/v1/sign", []byte(`{}`), time.Now(), "mw1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got != "alice" {
		t.Fatalf("caller in context = %q, want alice", got)
	}

	// Bad signature -> 401 through the middleware.
	bad := signReq(t, caller, priv, http.MethodPost, "/v1/sign", []byte(`{}`), time.Now(), "mw2")
	bad.Header.Set(HeaderSignature, hex.EncodeToString(make([]byte, ed25519.SignatureSize)))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, bad)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature: expected 401, got %d", rr.Code)
	}
}

// TestNonceCache_Concurrent exercises the cache under concurrent access: for a
// single (key,nonce) exactly one caller must win, the rest must see errReplay.
func TestNonceCache_Concurrent(t *testing.T) {
	c := newNonceCache(time.Minute, 1024)
	const n = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	var wins int
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.checkAndStore("k\x00same-nonce"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("expected exactly one winner for a shared nonce, got %d", wins)
	}
}

// TestNonceCache_Expiry confirms an expired nonce is purged and reusable.
func TestNonceCache_Expiry(t *testing.T) {
	c := newNonceCache(time.Minute, 1024)
	base := time.Now()
	c.now = func() time.Time { return base }
	if err := c.checkAndStore("id"); err != nil {
		t.Fatalf("first store: %v", err)
	}
	// Still within TTL -> replay.
	if err := c.checkAndStore("id"); err != errReplay {
		t.Fatalf("expected errReplay, got %v", err)
	}
	// Advance past TTL -> entry purged, reusable.
	c.now = func() time.Time { return base.Add(2 * time.Minute) }
	if err := c.checkAndStore("id"); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// TestNonceCache_Full fails closed at capacity.
func TestNonceCache_Full(t *testing.T) {
	c := newNonceCache(time.Minute, 2)
	if err := c.checkAndStore("a"); err != nil {
		t.Fatal(err)
	}
	if err := c.checkAndStore("b"); err != nil {
		t.Fatal(err)
	}
	if err := c.checkAndStore("c"); err != errNonceCacheFull {
		t.Fatalf("expected errNonceCacheFull, got %v", err)
	}
}
