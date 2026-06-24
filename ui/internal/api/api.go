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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// Statuser is the minimal view the API needs of the supervisor.
type Statuser interface {
	Status() supervisor.Status
}

// Wallet is the read-only wallet surface the API exposes.
type Wallet interface {
	SetWallet(mnemonic, network string, windowN int) (*wallet.Account, error)
	SetAccount(acct *wallet.Account) error
	Balance(ctx context.Context) (wallet.Balance, error)
	Addresses(ctx context.Context) (wallet.AddressView, error)
	Transactions(ctx context.Context) ([]wallet.Tx, error)
	Delegation(ctx context.Context) (wallet.DelegationView, error)
}

// Spender is the spending surface the API exposes: enabling spending (creating
// the encrypted keystore + deriving the account), building a send for preview,
// and confirming it (decrypt → sign → submit).
type Spender interface {
	SetWallet(mnemonic, network, password string) (*wallet.Account, error)
	Build(ctx context.Context, req spend.SendRequest) (spend.Preview, error)
	Confirm(ctx context.Context, pendingID, password string) (spend.TxResult, error)
}

const (
	defaultWindow  = 20
	minPasswordLen = 8
)

// NewHandler returns the loopback control-surface mux. network is the network
// the embedded node runs on; wallet requests must match it (or omit it).
// spa is the handler for the embedded SPA; it is registered as the catch-all
// route so that the specific API routes above take precedence on the mux.
func NewHandler(st Statuser, wl Wallet, sp Spender, network string, spa http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, st.Status())
	})

	mux.HandleFunc("POST /wallet", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mnemonic string `json:"mnemonic"`
			Network  string `json:"network"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		net, ok := resolveNetwork(w, req.Network, network)
		if !ok {
			return
		}
		acct, err := wl.SetWallet(req.Mnemonic, net, defaultWindow)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, acct)
	})

	mux.HandleFunc("GET /wallet/balance", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.Balance(r.Context())
		serve(w, v, err)
	}))
	mux.HandleFunc("GET /wallet/addresses", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.Addresses(r.Context())
		serve(w, v, err)
	}))
	mux.HandleFunc("GET /wallet/transactions", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.Transactions(r.Context())
		serve(w, v, err)
	}))
	mux.HandleFunc("GET /wallet/delegation", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := wl.Delegation(r.Context())
		serve(w, v, err)
	}))

	// Spending. Keystore setup derives + encrypts and so needs no synced node;
	// build/confirm are gated on a fully synced node (readyGate).
	mux.HandleFunc("POST /wallet/keystore", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mnemonic string `json:"mnemonic"`
			Network  string `json:"network"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		net, ok := resolveNetwork(w, req.Network, network)
		if !ok {
			return
		}
		if utf8.RuneCountInString(req.Password) < minPasswordLen {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("password must be at least %d characters", minPasswordLen),
			})
			return
		}
		acct, err := sp.SetWallet(req.Mnemonic, net, req.Password)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := wl.SetAccount(acct); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, acct)
	})

	mux.HandleFunc("POST /wallet/send", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req spend.SendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		pv, err := sp.Build(r.Context(), req)
		serve(w, pv, err)
	}))

	mux.HandleFunc("POST /wallet/send/{id}/confirm", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		res, err := sp.Confirm(r.Context(), r.PathValue("id"), req.Password)
		serve(w, res, err)
	}))

	// SPA catch-all: the specific API routes above take precedence on the mux;
	// everything else is served by the embedded frontend.
	mux.Handle("/", spa)

	return mux
}

// resolveNetwork returns the effective network for a wallet request, defaulting
// to the node's network and rejecting a mismatch (a wallet derived for a
// different network than the node always reads as empty). ok is false when it
// has already written an error response.
func resolveNetwork(w http.ResponseWriter, reqNet, nodeNet string) (string, bool) {
	if reqNet == "" {
		return nodeNet, true
	}
	if reqNet != nodeNet {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("network mismatch: node is running %s, request says %s", nodeNet, reqNet),
		})
		return "", false
	}
	return reqNet, true
}

// gated blocks wallet reads until the node can serve queries (ready or syncing).
func gated(st Statuser, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := st.Status().State
		if state != supervisor.StateReady && state != supervisor.StateSyncing {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "node not ready", "state": state,
			})
			return
		}
		next(w, r)
	}
}

// readyGate blocks spending until the node is fully synced (StateReady). It is
// stricter than gated (reads): a spend built against a partial UTxO view could
// select already-spent inputs.
func readyGate(st Statuser, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if state := st.Status().State; state != supervisor.StateReady {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "node not fully synced", "state": state,
			})
			return
		}
		next(w, r)
	}
}

// serve writes a query result, or maps a known error to its HTTP status code
// (falling back to 500). The spend sentinels carry the precise client-facing
// code so the caller can distinguish e.g. wrong-password from insufficient-funds.
func serve[T any](w http.ResponseWriter, v T, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, v)
	case errors.Is(err, wallet.ErrNoWallet), errors.Is(err, spend.ErrNoWallet):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: no wallet/keystore loaded
	case errors.Is(err, spend.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, errBody(err)) // 400
	case errors.Is(err, spend.ErrWrongPassword):
		writeJSON(w, http.StatusUnauthorized, errBody(err)) // 401
	case errors.Is(err, spend.ErrUnknownPending):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404
	case errors.Is(err, spend.ErrExpiredPending):
		writeJSON(w, http.StatusGone, errBody(err)) // 410
	case errors.Is(err, spend.ErrInsufficientFunds), errors.Is(err, spend.ErrSubmitRejected):
		// 422: the request was understood but cannot be fulfilled; the node's
		// structured rejection reason (for submit) rides along in the message.
		writeJSON(w, http.StatusUnprocessableEntity, errBody(err))
	default:
		writeJSON(w, http.StatusInternalServerError, errBody(err))
	}
}

func errBody(err error) map[string]string {
	return map[string]string{"error": err.Error()}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error encoding response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}
