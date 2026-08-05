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

// Adapted from github.com/ecadlabs/signatory (Apache-2.0); retains ECAD Labs copyright.
// Copyright (c) 2021 ECAD Labs

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/golang-jwt/jwt/v5"
)

type ctxKey int

const callerKey ctxKey = 0

// CallerFromContext returns the authenticated caller subject, or "".
func CallerFromContext(ctx context.Context) string {
	s, _ := ctx.Value(callerKey).(string)
	return s
}

// Validator parses+validates a bearer token and returns the caller subject.
type Validator func(token string) (subject string, err error)

// HS256Validator validates HS256 tokens against a shared secret (dev/simple mode).
// Production deployments should prefer JWKSValidator. issuer and audience are
// enforced when non-empty, identically to JWKSValidator. Without a configured
// caller ACL (signer.callers), any holder of a valid token may use any
// configured key.
func HS256Validator(secret []byte, issuer, audience string) Validator {
	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"HS256"}),
	}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	return func(token string) (string, error) {
		claims := jwt.RegisteredClaims{}
		_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			return secret, nil
		},
			opts...,
		)
		if err != nil {
			return "", err
		}
		return claims.Subject, nil
	}
}

// JWKSValidator validates RS256/ES256/EdDSA bearer tokens against a remote
// JWKS endpoint. The JWKS is fetched at construction — a misconfigured or
// unreachable endpoint fails boot — and refreshed in the background by keyfunc
// (1 h interval, rate-limited unknown-kid refresh). issuer and audience are
// enforced when non-empty. This is the production validator (design §12);
// HS256Validator remains for dev/simple deployments.
//
// Plain http is rejected unless the host is loopback (dev escape hatch).
func JWKSValidator(ctx context.Context, jwksURL, issuer, audience string) (Validator, error) {
	u, err := url.Parse(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("invalid jwks url: %w", err)
	}
	if u.Scheme != "https" && !backend.IsLoopbackHost(u.Hostname()) {
		return nil, errors.New("jwks_url must use https; plain http is allowed only for loopback addresses")
	}

	noError := false
	kf, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksURL}, keyfunc.Override{
		NoErrorReturnFirstHTTPReq: &noError,
	})
	if err != nil {
		return nil, fmt.Errorf("fetch jwks %q: %w", jwksURL, err)
	}
	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"RS256", "ES256", "EdDSA"}),
	}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	return func(token string) (string, error) {
		claims := jwt.RegisteredClaims{}
		if _, err := jwt.ParseWithClaims(token, &claims, kf.Keyfunc, opts...); err != nil {
			return "", err
		}
		return claims.Subject, nil
	}, nil
}

// write401 sends a properly-formed JSON 401 with WWW-Authenticate header.
func write401(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}
}

// Authentication errors returned by Authenticators. All map to 401 except the
// two below that carry their own HTTP status (see writeAuthError). Sentinels
// are unexported: the middleware maps them to responses, callers only see the
// generic wire messages so failures cannot be distinguished by attackers.
var (
	errInvalidToken     = errors.New("invalid token")
	errInvalidSignature = errors.New("invalid request signature")
	errUnknownKey       = errors.New("unknown authorized key")
	errStaleTimestamp   = errors.New("request timestamp outside allowed window")
	errReplay           = errors.New("request nonce already used")
	errNoCertIdentity   = errors.New("client certificate carries no usable identity")
	errNonceCacheFull   = errors.New("nonce cache full")
	errBodyTooLarge     = errors.New("request body too large")
	errNilRequest       = errors.New("nil request")
)

// Authenticator resolves the caller identity for a request from one credential
// scheme (JWT bearer, mTLS client cert, or authorized-keys request signing).
//
// It returns:
//   - (caller, true, nil)  when it positively identifies the caller;
//   - ("", false, nil)     when the request carries no credential for this
//     scheme — the chain proceeds to the next Authenticator (downgrade to a
//     weaker configured scheme is intentional and only happens when the
//     stronger scheme presented nothing);
//   - ("", true, err)      when a credential for this scheme IS present but is
//     invalid — the chain rejects immediately and does NOT fall through, so a
//     bad JWT cannot be retried as a signed request and vice-versa.
type Authenticator interface {
	Authenticate(r *http.Request) (caller string, ok bool, err error)
}

// jwtAuthenticator adapts a bearer-token Validator to the Authenticator chain.
type jwtAuthenticator struct{ validate Validator }

// JWTAuthenticator returns an Authenticator that validates Authorization:
// Bearer tokens with the supplied Validator.
func JWTAuthenticator(validate Validator) Authenticator { return jwtAuthenticator{validate} }

func (j jwtAuthenticator) Authenticate(r *http.Request) (string, bool, error) {
	if r == nil || r.Header == nil {
		return "", true, errNilRequest
	}
	authz := r.Header.Get("Authorization")
	// The "Bearer" scheme name is case-insensitive per RFC 7235 §2.1; match it
	// as such so e.g. "bearer <token>" is not mistaken for "no credential
	// presented" and downgraded to the next scheme in the chain.
	parts := strings.Fields(authz)
	if len(parts) == 0 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false, nil
	}
	if len(parts) != 2 {
		return "", true, errInvalidToken
	}
	subject, err := j.validate(parts[1])
	if err != nil || subject == "" {
		return "", true, errInvalidToken
	}
	return subject, true, nil
}

// writeAuthError maps an Authenticator error to an HTTP response. All auth
// failures collapse to a generic 401 except capacity/size conditions that have
// their own status.
func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNonceCacheFull):
		writeErr(w, http.StatusServiceUnavailable, "nonce cache full")
	case errors.Is(err, errBodyTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
	default:
		write401(w, "invalid credentials")
	}
}

// AuthMiddleware runs the ordered Authenticator chain, injecting the resolved
// caller subject into the request context (same context key the ACL reads).
// The first scheme that presents a credential decides the request: a valid
// credential authenticates it, an invalid one rejects it. Only schemes that
// present nothing are skipped. An empty chain fails closed (always 401).
func AuthMiddleware(chain []Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, a := range chain {
			caller, ok, err := a.Authenticate(r)
			if err != nil {
				writeAuthError(w, err)
				return
			}
			if !ok {
				continue
			}
			if caller == "" {
				write401(w, "invalid credentials")
				return
			}
			ctx := context.WithValue(r.Context(), callerKey, caller)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		write401(w, "authentication required")
	})
}

// JWTMiddleware authenticates requests with a single JWT Authenticator,
// injecting the caller subject into context. Retained for callers that only
// need bearer-token auth; the composable path is AuthMiddleware.
func JWTMiddleware(validate Validator, next http.Handler) http.Handler {
	return AuthMiddleware([]Authenticator{JWTAuthenticator(validate)}, next)
}
