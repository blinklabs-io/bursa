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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func tokenFor(t *testing.T, secret []byte, sub string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   sub,
		ExpiresAt: jwt.NewNumericDate(exp),
	})
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func TestJWTMiddleware(t *testing.T) {
	secret := []byte("test-secret")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if CallerFromContext(r.Context()) != "alice" {
			t.Errorf("expected caller alice, got %q", CallerFromContext(r.Context()))
		}
		w.WriteHeader(http.StatusOK)
	})
	h := JWTMiddleware(HS256Validator(secret), next)

	// valid
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, secret, "alice", time.Now().Add(time.Hour)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid token: expected 200, got %d", rr.Code)
	}

	// missing
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/keys", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: expected 401, got %d", rr.Code)
	}

	// expired
	req = httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, secret, "alice", time.Now().Add(-time.Hour)))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expired token: expected 401, got %d", rr.Code)
	}
}

// Test401JSON verifies that 401 responses carry proper JSON + headers.
func Test401JSON(t *testing.T) {
	secret := []byte("test-secret")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := JWTMiddleware(HS256Validator(secret), next)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/keys", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected application/json Content-Type, got %q", ct)
	}
	if rr.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", rr.Header().Get("WWW-Authenticate"))
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Errorf("response body is not valid JSON: %v", err)
	}
	if _, ok := body["error"]; !ok {
		t.Errorf("response JSON has no 'error' key")
	}
}

// TestNegativeAuthCases covers the four new negative cases required by Fix 8.
func TestNegativeAuthCases(t *testing.T) {
	secret := []byte("test-secret")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := JWTMiddleware(HS256Validator(secret), next)

	t.Run("alg=none", func(t *testing.T) {
		// Mint a "none" token; HS256Validator must reject it.
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{
			Subject:   "attacker",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		tokenStr, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("mint none token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("alg=none: expected 401, got %d", rr.Code)
		}
	})

	t.Run("alg=RS256", func(t *testing.T) {
		// Sign with an RSA key; HS256Validator must reject the algorithm.
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
			Subject:   "attacker",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		tokenStr, err := tok.SignedString(rsaKey)
		if err != nil {
			t.Fatalf("sign RS256 token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("alg=RS256: expected 401, got %d", rr.Code)
		}
	})

	t.Run("no-exp", func(t *testing.T) {
		// Token without ExpiresAt; WithExpirationRequired must reject it.
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Subject: "bob",
			// no ExpiresAt
		})
		tokenStr, err := tok.SignedString(secret)
		if err != nil {
			t.Fatalf("sign no-exp token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-exp token: expected 401, got %d", rr.Code)
		}
	})

	t.Run("empty-subject", func(t *testing.T) {
		// Valid HS256 token with empty subject; middleware must 401 because
		// subject == "" after validation.
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Subject:   "",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		tokenStr, err := tok.SignedString(secret)
		if err != nil {
			t.Fatalf("sign empty-sub token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("empty-subject token: expected 401, got %d", rr.Code)
		}
	})
}

// TestHandlerIntegration exercises the full composed Handler() path
// (JWT middleware + mux) with a valid token against GET /v1/keys → 200.
func TestHandlerIntegration(t *testing.T) {
	secret := []byte("integration-secret")
	srv, _ := newTestServer(t)

	// Replace the validator so it validates our secret.
	srv.validate = HS256Validator(secret)

	handler := srv.Handler()

	tok := tokenFor(t, secret, "integrationuser", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("integration GET /v1/keys: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
