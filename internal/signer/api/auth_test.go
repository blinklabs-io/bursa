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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
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
	h := JWTMiddleware(HS256Validator(secret, "", ""), next)

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
	h := JWTMiddleware(HS256Validator(secret, "", ""), next)

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
	h := JWTMiddleware(HS256Validator(secret, "", ""), next)

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
	srv.validate = HS256Validator(secret, "", "")

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

func rsaJWKSServer(t *testing.T, pub *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	body := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"%s","alg":"RS256","use":"sig","n":"%s","e":"%s"}]}`, kid, n, e)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
}

func rs256Token(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.RegisteredClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestJWKSValidator(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ts := rsaJWKSServer(t, &priv.PublicKey, "test-kid")
	defer ts.Close()

	validate, err := JWKSValidator(context.Background(), ts.URL, "https://issuer.example", "")
	if err != nil {
		t.Fatalf("JWKSValidator: %v", err)
	}

	good := jwt.RegisteredClaims{
		Subject:   "alice",
		Issuer:    "https://issuer.example",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	sub, err := validate(rs256Token(t, priv, "test-kid", good))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if sub != "alice" {
		t.Fatalf("expected subject alice, got %q", sub)
	}

	wrongIssuer := good
	wrongIssuer.Issuer = "https://evil.example"
	if _, err := validate(rs256Token(t, priv, "test-kid", wrongIssuer)); err == nil {
		t.Fatal("wrong issuer accepted")
	}

	expired := good
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	if _, err := validate(rs256Token(t, priv, "test-kid", expired)); err == nil {
		t.Fatal("expired token accepted")
	}

	// HS256 tokens must be rejected even if "signed" with something.
	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, good)
	hs, _ := hsTok.SignedString([]byte("0123456789abcdef0123456789abcdef"))
	if _, err := validate(hs); err == nil {
		t.Fatal("HS256 token accepted by JWKS validator")
	}

	if _, err := validate(rs256Token(t, priv, "unknown-kid", good)); err == nil {
		t.Fatal("unknown kid accepted")
	}
}

// TestJWKSValidator_RejectsPlainHTTPNonLoopback verifies that JWKSValidator
// refuses to construct when the JWKS URL uses plain http on a non-loopback host.
// Added as the failing test for Fix 1 (HTTPS enforcement).
func TestJWKSValidator_RejectsPlainHTTPNonLoopback(t *testing.T) {
	_, err := JWKSValidator(context.Background(), "http://idp.example.com/jwks.json", "", "")
	if err == nil {
		t.Fatal("expected error for plain http JWKS URL on non-loopback host")
	}
}

// TestJWKSValidator_FailsFastOnUnreachableJWKS verifies that JWKSValidator
// returns an error at construction time when the JWKS endpoint is unreachable.
// Added as the failing test for Fix 2 (fail-fast boot).
func TestJWKSValidator_FailsFastOnUnreachableJWKS(t *testing.T) {
	_, err := JWKSValidator(context.Background(), "http://127.0.0.1:1/jwks.json", "", "")
	if err == nil {
		t.Fatal("expected construction error for unreachable JWKS endpoint")
	}
}

// TestJWKSValidator_NoKidSingleKey pins the behavior for tokens without a kid
// header when the JWKS contains a single key. keyfunc falls back to trying the
// full key set, so these tokens should verify successfully.
// Added as the pinning test for Fix 4.
func TestJWKSValidator_NoKidSingleKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ts := rsaJWKSServer(t, &priv.PublicKey, "test-kid")
	defer ts.Close()

	validate, err := JWKSValidator(context.Background(), ts.URL, "", "")
	if err != nil {
		t.Fatalf("JWKSValidator: %v", err)
	}
	claims := jwt.RegisteredClaims{
		Subject:   "alice",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims) // no kid header
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	// keyfunc falls back to the full key set when kid is absent; with a single
	// JWKS key this verifies. Pinned so a keyfunc bump can't silently change it.
	if sub, err := validate(s); err != nil || sub != "alice" {
		t.Fatalf("no-kid token against single-key JWKS: sub=%q err=%v", sub, err)
	}
}

func TestJWKSValidator_Audience(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ts := rsaJWKSServer(t, &priv.PublicKey, "test-kid")
	defer ts.Close()

	validate, err := JWKSValidator(context.Background(), ts.URL, "", "bursa-signer")
	if err != nil {
		t.Fatalf("JWKSValidator: %v", err)
	}
	good := jwt.RegisteredClaims{
		Subject:   "alice",
		Audience:  jwt.ClaimStrings{"bursa-signer"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	if _, err := validate(rs256Token(t, priv, "test-kid", good)); err != nil {
		t.Fatalf("valid audience rejected: %v", err)
	}
	bad := good
	bad.Audience = jwt.ClaimStrings{"other-service"}
	if _, err := validate(rs256Token(t, priv, "test-kid", bad)); err == nil {
		t.Fatal("wrong audience accepted")
	}
}

// hs256Token mints an HS256 token with the given registered claims.
func hs256Token(t *testing.T, secret []byte, claims jwt.RegisteredClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

// TestHS256Validator_IssuerAudience verifies the shared-secret validator
// enforces issuer and audience claims when configured, matching JWKSValidator.
func TestHS256Validator_IssuerAudience(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	validate := HS256Validator(secret, "https://issuer.example", "bursa-signer")

	good := jwt.RegisteredClaims{
		Subject:   "alice",
		Issuer:    "https://issuer.example",
		Audience:  jwt.ClaimStrings{"bursa-signer"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	if _, err := validate(hs256Token(t, secret, good)); err != nil {
		t.Fatalf("valid issuer+audience rejected: %v", err)
	}

	wrongIssuer := good
	wrongIssuer.Issuer = "https://evil.example"
	if _, err := validate(hs256Token(t, secret, wrongIssuer)); err == nil {
		t.Fatal("wrong issuer accepted")
	}

	wrongAudience := good
	wrongAudience.Audience = jwt.ClaimStrings{"other-service"}
	if _, err := validate(hs256Token(t, secret, wrongAudience)); err == nil {
		t.Fatal("wrong audience accepted")
	}

	// A token missing the configured claims must also be rejected.
	missing := jwt.RegisteredClaims{
		Subject:   "alice",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	if _, err := validate(hs256Token(t, secret, missing)); err == nil {
		t.Fatal("token missing issuer/audience accepted")
	}
}
