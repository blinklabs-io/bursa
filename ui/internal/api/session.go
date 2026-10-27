// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

const (
	sessionCookieName = "bursa-control-session"
	sessionHeaderName = "X-Bursa-Session"
)

// NewSessionToken returns a process-local capability for the wallet control
// surface. It is delivered to the trusted frontend in the launch URL fragment,
// which browsers do not send to the HTTP server or in referrer headers.
func NewSessionToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate control session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func sessionTokenMatches(got, want string) bool {
	return len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func requestSessionToken(r *http.Request) string {
	if token := r.Header.Get(sessionHeaderName); token != "" {
		return token
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func isExtensionConnectorRoute(path string) bool {
	switch path {
	case "/connector/pair", "/connector/request", "/connector/self-revoke":
		return true
	default:
		return false
	}
}

func isControlRoute(path string) bool {
	return path == "/status" ||
		strings.HasPrefix(path, "/diagnostics") ||
		strings.HasPrefix(path, "/vault") ||
		strings.HasPrefix(path, "/wallet") ||
		strings.HasPrefix(path, "/connector/")
}

// sessionGuard protects the local control API with a random capability. Host
// and Origin checks remain defense in depth, but neither is treated as caller
// authentication because a local process can forge both.
func sessionGuard(token string, next http.Handler) http.Handler {
	if token == "" {
		panic("api: empty control session token")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !strictSameOrigin(r) || !sessionTokenMatches(r.Header.Get(sessionHeaderName), token) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			cookie := &http.Cookie{
				Name:     sessionCookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			}
			// The control surface listens on plain-HTTP loopback by default, where
			// WebKit-based webviews refuse to store a Secure cookie. Mark it Secure
			// whenever the request arrived over TLS so it never travels in cleartext
			// on a listener that terminates TLS itself.
			if r.TLS != nil {
				cookie.Secure = true
			}
			http.SetCookie(w, cookie)
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}

		// Health checks and static SPA files carry no wallet data. The extension
		// routes retain their independently paired bearer-token boundary.
		if r.URL.Path == "/health" || isExtensionConnectorRoute(r.URL.Path) || !isControlRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if !sessionTokenMatches(requestSessionToken(r), token) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
