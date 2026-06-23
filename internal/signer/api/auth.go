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

// JWTMiddleware authenticates requests, injecting the caller subject into context.
func JWTMiddleware(validate Validator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authz, prefix) {
			write401(w, "missing bearer token")
			return
		}
		subject, err := validate(strings.TrimPrefix(authz, prefix))
		if err != nil || subject == "" {
			write401(w, "invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), callerKey, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
