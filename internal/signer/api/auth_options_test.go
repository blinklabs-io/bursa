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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

func TestCheckJWKSURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		url       string
		plaintext bool
		ok        bool
	}{
		{"https://idp.example/jwks", false, true},
		{"http://127.0.0.1/jwks", false, true},
		{"http://localhost/jwks", false, true},
		{"http://idp.example/jwks", false, false},
		{"http://idp.example/jwks", true, true},
		{"https://idp.example/jwks", true, true},
		{"ftp://idp.example/jwks", true, false},
		{"file:///jwks", true, false},
	} {
		u, err := url.Parse(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		err = checkJWKSURL(u, tc.plaintext)
		if tc.ok != (err == nil) {
			t.Errorf(
				"checkJWKSURL(%q, plaintext=%v) = %v, want ok=%v",
				tc.url,
				tc.plaintext,
				err,
				tc.ok,
			)
		}
	}
	if checkJWKSURL(nil, true) == nil {
		t.Error("nil URL accepted")
	}
}

// With jwks_plaintext an http JWKS on any host passes the location policy:
// construction gets as far as the fetch. Without it the default refusal holds.
func TestJWKSValidatorWithOptions_Plaintext(t *testing.T) {
	t.Parallel()
	const jwksURL = "http://idp.invalid/jwks.json"
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := JWKSValidatorWithOptions(ctx, jwksURL, "", "", JWKSOptions{})
	if !errors.Is(err, errJWKSURLPolicy) {
		t.Fatalf("default: got %v, want errJWKSURLPolicy", err)
	}
	_, err = JWKSValidatorWithOptions(
		ctx,
		jwksURL,
		"",
		"",
		JWKSOptions{Plaintext: true},
	)
	if err == nil || errors.Is(err, errJWKSURLPolicy) {
		t.Fatalf("plaintext: got %v, want a fetch error", err)
	}
}

// A loopback JWKS that redirects to http on another host is refused by
// default and followed with jwks_plaintext.
func TestJWKSValidatorWithOptions_PlaintextRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(
		http.RedirectHandler("http://idp.invalid/jwks", http.StatusFound),
	)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := JWKSValidatorWithOptions(ctx, srv.URL, "", "", JWKSOptions{})
	if !errors.Is(err, errJWKSURLPolicy) {
		t.Fatalf("default: got %v, want errJWKSURLPolicy", err)
	}
	_, err = JWKSValidatorWithOptions(
		ctx,
		srv.URL,
		"",
		"",
		JWKSOptions{Plaintext: true},
	)
	if err == nil || errors.Is(err, errJWKSURLPolicy) {
		t.Fatalf("plaintext: got %v, want a fetch error", err)
	}
}

// TestAnonymousCaller covers signer.auth_none: a request without credentials
// is attributed to AnonymousCaller and the ACL still applies, while a
// presented credential is still verified by its scheme.
func TestAnonymousCaller(t *testing.T) {
	t.Parallel()
	srv, h, _ := newACLServer(t)
	body := signTxBody(t, h)
	sign := func(handler http.Handler, badSig bool) int {
		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/sign",
			bytes.NewReader(body),
		)
		if badSig {
			req.Header.Set(HeaderKey, "alice")
			req.Header.Set(
				HeaderTimestamp,
				strconv.FormatInt(time.Now().Unix(), 10),
			)
			req.Header.Set(HeaderNonce, "n1")
			req.Header.Set(HeaderSignature, "00")
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := sign(srv.Handler(), false); code != http.StatusUnauthorized {
		t.Fatalf("default without credentials: got %d, want 401", code)
	}

	srv.SetAnonymousCaller()
	handler := srv.Handler()
	if code := sign(handler, false); code != http.StatusForbidden {
		t.Fatalf("anonymous outside the ACL: got %d, want 403", code)
	}
	if code := sign(handler, true); code != http.StatusUnauthorized {
		t.Fatalf("invalid credential: got %d, want 401", code)
	}

	srv.acl = NewCallerACL(map[string][]backend.KeyHash{AnonymousCaller: {h}})
	if code := sign(handler, false); code != http.StatusOK {
		t.Fatalf("anonymous in the ACL: got %d, want 200", code)
	}
}
