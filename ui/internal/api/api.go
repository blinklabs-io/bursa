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

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/multisig"
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
	SignData(addr string, message []byte, password string) (signatureHex, keyHex string, err error)
	VerifyData(signatureHex, keyHex string, message []byte, hashed bool, expectedAddress string) (valid bool, address string, err error)
	ExportUnsigned(pendingID string) (spend.UnsignedTx, error)
	SignTx(unsignedTxCBOR, password string) (spend.Witness, error)
	SubmitSigned(ctx context.Context, unsignedTxCBOR, witnessCBOR string) (spend.TxResult, error)
}

// MultiSig is the native multi-signature surface the API exposes: managing saved
// multi-sig accounts (list/create/get/delete), sharing the wallet's own CIP-1854
// participant key, and the spend flow (balance/build/sign/submit) against a saved
// account's script address.
type MultiSig interface {
	List() ([]multisig.Account, error)
	Get(id string) (multisig.Account, error)
	Create(req multisig.CreateRequest) (multisig.Account, error)
	Delete(id string) error
	MyKey(password string) (multisig.MyKey, error)
	Balance(ctx context.Context, id string) (string, error)
	Build(ctx context.Context, id string, req multisig.BuildRequest) (multisig.UnsignedTx, error)
	Sign(unsignedTxCBOR, password string) (multisig.Witness, error)
	Submit(ctx context.Context, id, unsignedTxCBOR string, witnessCBORs []string) (multisig.TxResult, error)
}

const defaultWindow = 20

// NewHandler returns the loopback control-surface mux. network is the network
// the embedded node runs on; wallet requests must match it (or omit it).
// spa is the handler for the embedded SPA; it is registered as the catch-all
// route so that the specific API routes above take precedence on the mux.
func NewHandler(st Statuser, wl Wallet, sp Spender, ms MultiSig, network string, spa http.Handler) http.Handler {
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
		if utf8.RuneCountInString(req.Password) < keystore.MinPasswordLen {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("password must be at least %d characters", keystore.MinPasswordLen),
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

	// CIP-8 / CIP-30 message signing. Ungated: signing is fully offline (no node
	// needed) — it requires only the keystore (spending password) to unlock the
	// key. A read-only wallet has no keystore and gets 409.
	mux.HandleFunc("POST /wallet/sign-data", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address  string `json:"address"`
			Message  string `json:"message"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		sig, key, err := sp.SignData(req.Address, []byte(req.Message), req.Password)
		serve(w, map[string]string{"signature": sig, "key": key}, err)
	})

	// CIP-8 / CIP-30 message verification — the inverse of sign-data. Pure
	// crypto: ungated, no node, no keystore (a read-only wallet can verify too).
	mux.HandleFunc("POST /wallet/verify-data", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Signature       string `json:"signature"`
			Key             string `json:"key"`
			Message         string `json:"message"`
			Hashed          bool   `json:"hashed"`
			ExpectedAddress string `json:"expected_address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		valid, addr, err := sp.VerifyData(req.Signature, req.Key, []byte(req.Message), req.Hashed, req.ExpectedAddress)
		serve(w, map[string]any{"valid": valid, "address": addr}, err)
	})

	// Air-gap step 1 (online instance): export the completed-but-unsigned tx for
	// a pending send + the key-hashes that must sign it. Built against a synced
	// node's UTxO view, so it shares the send flow's readyGate.
	mux.HandleFunc("POST /wallet/send/{id}/export-unsigned", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := sp.ExportUnsigned(r.PathValue("id"))
		serve(w, v, err)
	}))

	// Air-gap step 2 (offline instance): sign an unsigned tx with the active
	// wallet's key. Ungated like sign-data — pure crypto over the keystore, no
	// node needed; this is what the air-gapped machine runs.
	mux.HandleFunc("POST /wallet/sign-tx", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UnsignedTxCBOR string `json:"unsigned_tx_cbor"`
			Password       string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		v, err := sp.SignTx(req.UnsignedTxCBOR, req.Password)
		serve(w, v, err)
	})

	// Air-gap step 3 (online instance): attach the offline witness to the
	// unsigned tx and broadcast. Needs a synced node (readyGate).
	mux.HandleFunc("POST /wallet/submit-signed", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UnsignedTxCBOR string `json:"unsigned_tx_cbor"`
			WitnessCBOR    string `json:"witness_cbor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		v, err := sp.SubmitSigned(r.Context(), req.UnsignedTxCBOR, req.WitnessCBOR)
		serve(w, v, err)
	}))

	// --- Native multi-signature ---------------------------------------------
	// Account CRUD is pure local state (compose script + derive address +
	// persist), so it is ungated. Balance/build/submit query/broadcast through a
	// synced node (readyGate); sign is pure crypto over the keystore (ungated).

	// List saved multi-sig accounts.
	mux.HandleFunc("GET /wallet/multisig", func(w http.ResponseWriter, _ *http.Request) {
		v, err := ms.List()
		serve(w, v, err)
	})

	// Create a saved multi-sig account from a policy.
	mux.HandleFunc("POST /wallet/multisig", func(w http.ResponseWriter, r *http.Request) {
		var req multisig.CreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		net, ok := resolveNetwork(w, req.Network, network)
		if !ok {
			return
		}
		req.Network = net
		v, err := ms.Create(req)
		serve(w, v, err)
	})

	// The active wallet's own CIP-1854 multi-sig participant key, to share. Needs
	// the spending password to unlock the seed; ungated (pure crypto, no node).
	mux.HandleFunc("POST /wallet/multisig/my-key", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		v, err := ms.MyKey(req.Password)
		serve(w, v, err)
	})

	// Fetch one saved account.
	mux.HandleFunc("GET /wallet/multisig/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, err := ms.Get(r.PathValue("id"))
		serve(w, v, err)
	})

	// Delete a saved account.
	mux.HandleFunc("DELETE /wallet/multisig/{id}", func(w http.ResponseWriter, r *http.Request) {
		err := ms.Delete(r.PathValue("id"))
		serve(w, map[string]string{"status": "deleted"}, err)
	})

	// Balance held at the account's script address.
	mux.HandleFunc("GET /wallet/multisig/{id}/balance", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := ms.Balance(r.Context(), r.PathValue("id"))
		serve(w, map[string]string{"lovelace": v}, err)
	}))

	// Build an unsigned spend from the account's script address.
	mux.HandleFunc("POST /wallet/multisig/{id}/build", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req multisig.BuildRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		v, err := ms.Build(r.Context(), r.PathValue("id"), req)
		serve(w, v, err)
	}))

	// Co-sign an unsigned multi-sig tx with the wallet's CIP-1854 key. Ungated
	// (pure crypto over the keystore, no node), like sign-tx.
	mux.HandleFunc("POST /wallet/multisig/sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UnsignedTxCBOR string `json:"unsigned_tx_cbor"`
			Password       string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		v, err := ms.Sign(req.UnsignedTxCBOR, req.Password)
		serve(w, v, err)
	})

	// Attach the script + collected witnesses and broadcast (threshold enforced).
	mux.HandleFunc("POST /wallet/multisig/{id}/submit", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UnsignedTxCBOR string   `json:"unsigned_tx_cbor"`
			Witnesses      []string `json:"witnesses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		v, err := ms.Submit(r.Context(), r.PathValue("id"), req.UnsignedTxCBOR, req.Witnesses)
		serve(w, v, err)
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
	case errors.Is(err, wallet.ErrNoWallet), errors.Is(err, spend.ErrNoWallet),
		errors.Is(err, multisig.ErrNoKeystore):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: no wallet/keystore loaded
	case errors.Is(err, spend.ErrInvalidRequest),
		errors.Is(err, spend.ErrInvalidTx),
		errors.Is(err, spend.ErrInvalidWitness),
		errors.Is(err, multisig.ErrInvalidRequest),
		errors.Is(err, multisig.ErrInvalidTx),
		errors.Is(err, multisig.ErrInvalidWitness):
		writeJSON(w, http.StatusBadRequest, errBody(err)) // 400
	case errors.Is(err, spend.ErrWrongPassword), errors.Is(err, multisig.ErrWrongPassword):
		writeJSON(w, http.StatusUnauthorized, errBody(err)) // 401
	case errors.Is(err, spend.ErrUnknownPending), errors.Is(err, multisig.ErrUnknownAccount):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404
	case errors.Is(err, spend.ErrExpiredPending):
		writeJSON(w, http.StatusGone, errBody(err)) // 410
	case errors.Is(err, spend.ErrInsufficientFunds), errors.Is(err, spend.ErrSubmitRejected),
		errors.Is(err, multisig.ErrInsufficientFunds), errors.Is(err, multisig.ErrSubmitRejected):
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
