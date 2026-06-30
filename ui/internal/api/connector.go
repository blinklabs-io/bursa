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

// Package api — connector.go holds all /connector/* HTTP wiring for the
// CIP-30 dApp connector. Routes are registered in later tasks; this file
// currently provides the token + CORS middleware that guards them.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/connector"
)

// connectorTokenVerifier is the minimal surface of connector.Service that the
// middleware needs. *connector.Service satisfies this interface.
type connectorTokenVerifier interface {
	VerifyToken(token, extensionID string) bool
}

// connectorMiddleware returns a middleware that:
//  1. Sets CORS headers (Access-Control-Allow-Origin, -Headers, -Methods) on
//     every response when a pairing exists (allowedExtensionID returns ok).
//  2. Responds 204 to OPTIONS preflight requests (no body).
//  3. For every path EXCEPT /connector/pair, reads the X-Bursa-Token and
//     Origin headers and rejects the request with 401 if
//     svc.VerifyToken(token, origin) is false.
//  4. Passes all other requests to next.
func connectorMiddleware(svc connectorTokenVerifier, allowedExtensionID func() (string, bool)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers when paired.
			if extID, ok := allowedExtensionID(); ok {
				w.Header().Set("Access-Control-Allow-Origin", extID)
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Bursa-Token")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			}

			// Handle OPTIONS preflight — respond 204, no body.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// /connector/pair passes through: the extension has no token yet
			// during the pairing handshake. Match the path exactly — a suffix
			// match would also exempt crafted paths like /evil/connector/pair,
			// widening the unauthenticated surface.
			if r.URL.Path == "/connector/pair" {
				next.ServeHTTP(w, r)
				return
			}

			// All other /connector/* paths require a valid bearer token.
			token := r.Header.Get("X-Bursa-Token")
			origin := r.Header.Get("Origin")
			if !svc.VerifyToken(token, origin) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Ensure *connector.Service satisfies connectorTokenVerifier at compile time.
var _ connectorTokenVerifier = (*connector.Service)(nil)

// isLoopbackHost returns true when host is a loopback address.
// It accepts any port (mobile uses a dynamic loopback port) and handles IPv6
// literals. If SplitHostPort fails (no port), the raw host is checked directly.
func isLoopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

// sameOrigin returns true when the request comes from the same origin as the
// API server. Same-origin browser requests typically omit the Origin header
// entirely, so an absent header is treated as same-origin. When Origin is
// present, the Host must be a loopback address (DNS-rebinding defence) and the
// Origin must match the API server's own scheme+host.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		// No Origin header: same-origin direct navigation, allow.
		return true
	}
	// Reject if the Host is not a loopback address: a DNS-rebound host
	// (e.g. Host: evil.com:8090 → 127.0.0.1) would otherwise pass the
	// exact-match check below.
	if !isLoopbackHost(r.Host) {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return o == scheme+"://"+r.Host
}

func strictSameOrigin(r *http.Request) bool {
	if r.Header.Get("Origin") == "" {
		return false
	}
	return sameOrigin(r)
}

// registerConnector registers all /connector/* routes on mux.
//
// Extension-facing routes (pair, request) are wrapped by connectorMiddleware,
// which applies CORS headers and token verification. The /connector/pair route
// is exempt from the token check inside the middleware (pairing handshake).
// The mux-level patterns are registered without a method so that OPTIONS
// preflight requests also reach the middleware before the sub-mux dispatches.
//
// SPA-facing routes (events, grants, grants/revoke, decide, unpair) are NOT
// token-gated; each handler guards itself via sameOrigin().
func registerConnector(mux *http.ServeMux, svc *connector.Service) {
	// Extension-facing: CORS + token (pair is token-exempt inside the middleware).
	ext := http.NewServeMux()
	ext.HandleFunc("POST /connector/pair", handleConnectorPair(svc))
	ext.HandleFunc("POST /connector/request", handleConnectorRequest(svc))
	wrapped := connectorMiddleware(svc, svc.PairedExtensionID)(ext)
	mux.Handle("/connector/pair", wrapped)
	mux.Handle("/connector/request", wrapped)

	// SPA-facing (same-origin guarded in-handler), NOT token-gated.
	mux.HandleFunc("GET /connector/events", handleConnectorEvents(svc))
	mux.HandleFunc("GET /connector/grants", handleConnectorGrants(svc))
	mux.HandleFunc("POST /connector/grants/revoke", handleConnectorGrantsRevoke(svc))
	mux.HandleFunc("POST /connector/decide", handleConnectorDecide(svc))
	mux.HandleFunc("POST /connector/unpair", handleConnectorUnpair(svc))
	mux.HandleFunc("POST /connector/pending-pairings", handleConnectorPendingPairings(svc))
}

// handleConnectorGrants handles GET /connector/grants.
//
// SPA-facing — requires same-origin request (no Origin header or Origin matches
// the server's own scheme+host). Returns the list of granted origins plus the
// paired extension ID if one exists.
func handleConnectorGrants(svc *connector.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
			return
		}
		extID, paired := svc.PairedExtensionID()
		if !paired {
			extID = ""
		}
		origins := svc.Grants()
		if origins == nil {
			origins = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"origins":      origins,
			"paired":       paired,
			"extension_id": extID,
		})
	}
}

// handleConnectorGrantsRevoke handles POST /connector/grants/revoke.
//
// SPA-facing — requires same-origin request. Body: {"origin": string}.
// Revokes the given origin's grant and responds 200 {"ok":true}; empty origin
// or revocation error responds 400.
func handleConnectorGrantsRevoke(svc *connector.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
			return
		}
		var body struct {
			Origin string `json:"origin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if body.Origin == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "origin is required"})
			return
		}
		if err := svc.RevokeGrant(body.Origin); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// handleConnectorDecide handles POST /connector/decide.
//
// SPA-facing — requires same-origin request. Body: {"id": string, "approved":
// bool, "password": string}. Resolves a pending consent prompt.
// Unknown id → 404; other error → 400.
func handleConnectorDecide(svc *connector.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
			return
		}
		var body struct {
			ID       string `json:"id"`
			Approved bool   `json:"approved"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		err := svc.Decide(body.ID, connector.Decision{Approved: body.Approved, Password: body.Password})
		if err != nil {
			if errors.Is(err, connector.ErrUnknownRequest) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown request id"})
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// handleConnectorUnpair handles POST /connector/unpair.
//
// SPA-facing — requires same-origin request. Unpairs the current extension.
// The operation is idempotent (Unpair tolerates absence). Always responds 200
// {"ok":true} when same-origin.
func handleConnectorUnpair(svc *connector.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
			return
		}
		_ = svc.Unpair()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// handleConnectorPendingPairings handles POST /connector/pending-pairings.
//
// SPA-facing — requires a strict same-origin browser request with an Origin
// header. Pairing codes are intentionally not exposed via no-Origin GETs because
// any local process could otherwise scrape the code and self-confirm pairing.
func handleConnectorPendingPairings(svc *connector.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strictSameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
			return
		}
		pairings := svc.PendingPairings()
		writeJSON(w, http.StatusOK, pairings)
	}
}

// handleConnectorEvents handles GET /connector/events.
//
// This is a Server-Sent Events (SSE) stream consumed by the Bursa SPA. It is
// guarded by sameOrigin() (like the other SPA-facing routes) and does NOT
// require the extension bearer token — that is scoped to extension-facing
// routes only.
//
// On connect:
//  1. Emits the current pending snapshot (one event per request).
//  2. Streams new requests as they arrive via svc.Subscribe().
//  3. Sends a ": keepalive" SSE comment every 20 s to prevent proxy timeouts.
//  4. Returns when the client disconnects (r.Context().Done()).
func handleConnectorEvents(svc *connector.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// SPA-facing: enforce same-origin before opening the stream, matching the
		// other /connector/* SPA routes. Without this guard a cross-origin page
		// could open the SSE stream and observe pending dApp request metadata.
		if !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		// writeEvent writes a single SSE data event and flushes.
		writeEvent := func(req connector.Request) {
			b, err := json.Marshal(req)
			if err != nil {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}

		ch, cancel := svc.Subscribe()
		defer cancel()

		// Emit the current pending snapshot so the SPA starts with full state.
		for _, req := range svc.Pending() {
			writeEvent(req)
		}

		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case req := <-ch:
				writeEvent(req)
			case <-ticker.C:
				fmt.Fprint(w, ": keepalive\n\n")
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
}

// connectorErrorCode maps a CIP-30 method + error to the HTTP status, CIP-30
// error_code integer, and info string to return to the caller.
//
// CIP-30 error_code constants:
//
//	APIError:       -3 Refused, -2 InternalError, -1 InvalidRequest
//	TxSignError:     2 UserDeclined
//	DataSignError:   3 UserDeclined
//	TxSendError:     1 Refused
func connectorErrorCode(method string, err error) (httpStatus int, code int, info string) {
	switch {
	case errors.Is(err, connector.ErrInvalidParams), errors.Is(err, connector.ErrInvalidOrigin):
		return http.StatusBadRequest, -1, err.Error()
	case errors.Is(err, connector.ErrNotGranted), errors.Is(err, connector.ErrRefused):
		return http.StatusForbidden, -3, err.Error()
	case errors.Is(err, connector.ErrTimeout):
		return http.StatusRequestTimeout, -3, "request timed out"
	case errors.Is(err, connector.ErrUserDeclined):
		switch method {
		case "signData":
			return http.StatusForbidden, 3, err.Error()
		case "signTx":
			return http.StatusForbidden, 2, err.Error()
		case "submitTx":
			return http.StatusForbidden, 1, err.Error()
		default:
			return http.StatusForbidden, -3, err.Error()
		}
	default:
		return http.StatusInternalServerError, -2, err.Error()
	}
}

// handleConnectorRequest handles POST /connector/request.
//
// JSON body: { "origin": string, "method": string, "params": json.RawMessage }
//
// On success → 200 {"result": <raw JSON>}.
// On error   → CIP-30 error body {"error_code": N, "info": "<msg>"}.
func handleConnectorRequest(svc *connector.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Origin string          `json:"origin"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error_code": -1,
				"info":       "invalid JSON body",
			})
			return
		}
		if body.Method == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error_code": -1,
				"info":       "method is required",
			})
			return
		}

		result, err := svc.Handle(r.Context(), body.Origin, body.Method, body.Params)
		if err != nil {
			status, code, info := connectorErrorCode(body.Method, err)
			writeJSON(w, status, map[string]any{
				"error_code": code,
				"info":       info,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]json.RawMessage{
			"result": result,
		})
	}
}

// handleConnectorPair handles POST /connector/pair.
//
// JSON body: { "extension_id": string, "code": string }
//
// Two modes:
//   - Initiate (code == ""): calls svc.BeginPair and responds 202 {"status":"pending"}.
//     The generated code is NOT returned — it is shown inside the Bursa app so the
//     user can transfer it out-of-band to the extension. Returning it here would
//     allow any local caller to self-pair without user interaction.
//   - Confirm (code != ""): calls svc.ConfirmPair and responds 200 {"token":"..."}.
//     Returns 403 on a code mismatch, 400 for other errors.
func handleConnectorPair(svc *connector.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ExtensionID string `json:"extension_id"`
			Code        string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if req.ExtensionID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "extension_id is required"})
			return
		}

		if req.Code == "" {
			// Initiate: generate + cache a pairing code for display in the Bursa UI.
			// Do NOT return the code in the HTTP response — that would allow any
			// local unauthenticated caller to pair without user approval.
			svc.BeginPair(req.ExtensionID)
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
			return
		}

		// Confirm: validate the code and mint a bearer token.
		token, err := svc.ConfirmPair(req.ExtensionID, req.Code)
		if err != nil {
			if errors.Is(err, connector.ErrPairCodeMismatch) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "pairing code mismatch"})
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	}
}
