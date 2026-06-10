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
	"fmt"
	"net/http"
	"strings"

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
// Production deployments use a JWKS-backed validator (RS256/ES256); the interface
// is identical.
//
// Single trust domain: Phase 1 HS256 auth grants ANY holder of a valid token
// access to ANY configured key. Per-caller key scoping arrives with the JWKS
// follow-up.
func HS256Validator(secret []byte) Validator {
	return func(token string) (string, error) {
		claims := jwt.RegisteredClaims{}
		_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			return secret, nil
		},
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{"HS256"}),
		)
		if err != nil {
			return "", err
		}
		return claims.Subject, nil
	}
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
