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
	"sync"
	"time"
)

const sessionHeaderName = "X-Bursa-Session"

const eventTicketTTL = 15 * time.Second

type eventTicketStore struct {
	mu      sync.Mutex
	tickets map[string]time.Time
}

func newEventTicketStore() *eventTicketStore {
	return &eventTicketStore{tickets: make(map[string]time.Time)}
}

func (s *eventTicketStore) issue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate event ticket: %w", err)
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for value, expires := range s.tickets {
		if !expires.After(now) {
			delete(s.tickets, value)
		}
	}
	s.tickets[ticket] = now.Add(eventTicketTTL)
	return ticket, nil
}

func (s *eventTicketStore) consume(ticket string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.tickets[ticket]
	delete(s.tickets, ticket)
	return ok && expires.After(now)
}

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
	return len(got) == len(want) &&
		subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func requestSessionToken(r *http.Request) string {
	return r.Header.Get(sessionHeaderName)
}

func isExtensionConnectorRoute(path string) bool {
	switch path {
	case "/connector/pair", "/connector/challenge", "/connector/request", "/connector/self-revoke":
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
		strings.HasPrefix(path, "/remote-submission") ||
		strings.HasPrefix(path, "/connector/")
}

// sessionGuard protects the local control API with a random capability. Host
// and Origin checks remain defense in depth, but neither is treated as caller
// authentication because a local process can forge both.
func sessionGuard(token string, next http.Handler) http.Handler {
	if token == "" {
		panic("api: empty control session token")
	}
	eventTickets := newEventTicketStore()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !strictSameOrigin(r) ||
				!sessionTokenMatches(r.Header.Get(sessionHeaderName), token) {
				writeJSON(
					w,
					http.StatusUnauthorized,
					map[string]string{"error": "unauthorized"},
				)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		if r.URL.Path == "/session/events-ticket" {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !strictSameOrigin(r) ||
				!sessionTokenMatches(requestSessionToken(r), token) {
				writeJSON(
					w,
					http.StatusUnauthorized,
					map[string]string{"error": "unauthorized"},
				)
				return
			}
			ticket, err := eventTickets.issue()
			if err != nil {
				writeJSON(
					w,
					http.StatusInternalServerError,
					map[string]string{"error": "event authorization unavailable"},
				)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, map[string]string{"ticket": ticket})
			return
		}
		if r.URL.Path == "/connector/events" &&
			r.Method == http.MethodGet &&
			eventTickets.consume(r.URL.Query().Get("ticket")) {
			query := r.URL.Query()
			query.Del("ticket")
			r.URL.RawQuery = query.Encode()
			next.ServeHTTP(w, r)
			return
		}

		// Health checks and static SPA files carry no wallet data. The extension
		// routes retain their independently paired signature boundary.
		if r.URL.Path == "/health" || isExtensionConnectorRoute(r.URL.Path) ||
			!isControlRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if !sessionTokenMatches(requestSessionToken(r), token) {
			writeJSON(
				w,
				http.StatusUnauthorized,
				map[string]string{"error": "unauthorized"},
			)
			return
		}
		next.ServeHTTP(w, r)
	})
}
