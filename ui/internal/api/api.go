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
	"github.com/blinklabs-io/bursa/ui/internal/poolops"
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
}

// PoolOps is the Stake Pool Operations surface the API exposes. Credential
// generation and seed-derived certificate/opcert building need the active
// wallet + spending password; the air-gap builders (pool ID, opcert payload /
// assembly, metadata, air-gap registration cert) need neither. Submission
// (retirement) needs a synced node. It operates on the active wallet.
type PoolOps interface {
	SetAccount(acct *wallet.Account)
	Credentials(password string) (poolops.Credentials, error)
	KESPeriod(ctx context.Context) (poolops.KESPeriodInfo, error)
	IssueOpCert(password string, kesIndex uint32, issueNumber, kesPeriod uint64) (poolops.OpCert, error)
	RotateKES(password string, newKESIndex uint32, prevIssueNumber, kesPeriod uint64) (poolops.OpCert, error)
	OpCertPayload(kesVKeyHex string, issueNumber, kesPeriod uint64) (poolops.OpCertPayload, error)
	AssembleOpCert(coldVKeyHex, kesVKeyHex, signatureHex string, issueNumber, kesPeriod uint64) (poolops.OpCert, error)
	BuildMetadata(in poolops.MetadataInput) (poolops.MetadataResult, error)
	PoolIDFromColdVKey(coldVKeyHex string) (poolID, poolIDHex string, err error)
	BuildRegistrationFromSeed(password string, p poolops.RegistrationParams) (poolops.CertResult, error)
	BuildRegistrationAirGap(p poolops.AirGapRegistrationParams) (poolops.CertResult, error)
	BuildRetirementCert(password, coldVKeyHex string, epoch uint64) (poolops.CertResult, error)
	SubmitRetirement(ctx context.Context, password string, epoch uint64) (poolops.TxResult, error)
}

const defaultWindow = 20

// NewHandler returns the loopback control-surface mux. network is the network
// the embedded node runs on; wallet requests must match it (or omit it).
// spa is the handler for the embedded SPA; it is registered as the catch-all
// route so that the specific API routes above take precedence on the mux.
func NewHandler(st Statuser, wl Wallet, sp Spender, po PoolOps, network string, spa http.Handler) http.Handler {
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
		// Pool operations run on the same active wallet; attach it so the SPO
		// toolkit can derive cold/VRF/KES credentials and build certificates.
		po.SetAccount(acct)
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

	registerPoolRoutes(mux, st, po)

	// SPA catch-all: the specific API routes above take precedence on the mux;
	// everything else is served by the embedded frontend.
	mux.Handle("/", spa)

	return mux
}

// registerPoolRoutes wires the Stake Pool Operations (SPO) endpoints under
// /wallet/pool/. Air-gap builders (pool ID, opcert payload/assembly, metadata,
// air-gap registration cert) are ungated and need no node — they are pure
// transforms over operator-supplied data. Seed-derived credential/cert/opcert
// building needs the active wallet + spending password but no node (offline).
// KES-period and retirement submission need a node (gated / readyGate).
func registerPoolRoutes(mux *http.ServeMux, st Statuser, po PoolOps) {
	// 1. Credentials (active wallet + password; offline).
	mux.HandleFunc("POST /wallet/pool/credentials", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.Credentials(req.Password)
		serve(w, v, err)
	})

	// 2. KES period (node tip + genesis; gated on a queryable node).
	mux.HandleFunc("GET /wallet/pool/kes-period", gated(st, func(w http.ResponseWriter, r *http.Request) {
		v, err := po.KESPeriod(r.Context())
		serve(w, v, err)
	}))

	// 2. Operational certificate: issue (seed).
	mux.HandleFunc("POST /wallet/pool/opcert", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password    string `json:"password"`
			KESIndex    uint32 `json:"kes_index"`
			IssueNumber uint64 `json:"issue_number"`
			KESPeriod   uint64 `json:"kes_period"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.IssueOpCert(req.Password, req.KESIndex, req.IssueNumber, req.KESPeriod)
		serve(w, v, err)
	})

	// 2. Operational certificate: KES rotation (seed) — new KES key + counter bump.
	mux.HandleFunc("POST /wallet/pool/opcert/rotate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password        string `json:"password"`
			NewKESIndex     uint32 `json:"new_kes_index"`
			PrevIssueNumber uint64 `json:"prev_issue_number"`
			KESPeriod       uint64 `json:"kes_period"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.RotateKES(req.Password, req.NewKESIndex, req.PrevIssueNumber, req.KESPeriod)
		serve(w, v, err)
	})

	// Air-gap: opcert to-be-signed payload (no wallet needed).
	mux.HandleFunc("POST /wallet/pool/opcert/payload", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			KESVKeyHex  string `json:"kes_vkey_hex"`
			IssueNumber uint64 `json:"issue_number"`
			KESPeriod   uint64 `json:"kes_period"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.OpCertPayload(req.KESVKeyHex, req.IssueNumber, req.KESPeriod)
		serve(w, v, err)
	})

	// Air-gap: assemble opcert from an externally-produced cold-key signature.
	mux.HandleFunc("POST /wallet/pool/opcert/assemble", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ColdVKeyHex  string `json:"cold_vkey_hex"`
			KESVKeyHex   string `json:"kes_vkey_hex"`
			SignatureHex string `json:"signature_hex"`
			IssueNumber  uint64 `json:"issue_number"`
			KESPeriod    uint64 `json:"kes_period"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.AssembleOpCert(req.ColdVKeyHex, req.KESVKeyHex, req.SignatureHex, req.IssueNumber, req.KESPeriod)
		serve(w, v, err)
	})

	// 6. Metadata builder (pure transform; no wallet/node).
	mux.HandleFunc("POST /wallet/pool/metadata", func(w http.ResponseWriter, r *http.Request) {
		var in poolops.MetadataInput
		if !decodeBody(w, r, &in) {
			return
		}
		v, err := po.BuildMetadata(in)
		serve(w, v, err)
	})

	// Air-gap import: pool ID from an external cold vkey (pure transform).
	mux.HandleFunc("POST /wallet/pool/id", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ColdVKeyHex string `json:"cold_vkey_hex"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		id, idHex, err := po.PoolIDFromColdVKey(req.ColdVKeyHex)
		serve(w, map[string]string{"pool_id": id, "pool_id_hex": idHex}, err)
	})

	// 3/4. Registration / update certificate (seed): build the canonical cert.
	mux.HandleFunc("POST /wallet/pool/registration", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
			poolops.RegistrationParams
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.BuildRegistrationFromSeed(req.Password, req.RegistrationParams)
		serve(w, v, err)
	})

	// 3/4. Registration / update certificate (air-gap): build from imported keys.
	mux.HandleFunc("POST /wallet/pool/registration/airgap", func(w http.ResponseWriter, r *http.Request) {
		var p poolops.AirGapRegistrationParams
		if !decodeBody(w, r, &p) {
			return
		}
		v, err := po.BuildRegistrationAirGap(p)
		serve(w, v, err)
	})

	// 5. Retirement certificate (seed or air-gap cold vkey).
	mux.HandleFunc("POST /wallet/pool/retirement/cert", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password    string `json:"password"`
			ColdVKeyHex string `json:"cold_vkey_hex"`
			Epoch       uint64 `json:"epoch"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.BuildRetirementCert(req.Password, req.ColdVKeyHex, req.Epoch)
		serve(w, v, err)
	})

	// 5. Retirement transaction submission (seed; needs a fully synced node).
	mux.HandleFunc("POST /wallet/pool/retirement/submit", readyGate(st, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
			Epoch    uint64 `json:"epoch"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		v, err := po.SubmitRetirement(r.Context(), req.Password, req.Epoch)
		serve(w, v, err)
	}))
}

// decodeBody decodes a JSON request body into v, writing a 400 and returning
// false on malformed input.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
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
	case errors.Is(err, wallet.ErrNoWallet), errors.Is(err, spend.ErrNoWallet), errors.Is(err, poolops.ErrNoWallet):
		writeJSON(w, http.StatusConflict, errBody(err)) // 409: no wallet/keystore loaded
	case errors.Is(err, spend.ErrInvalidRequest), errors.Is(err, poolops.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, errBody(err)) // 400
	case errors.Is(err, spend.ErrWrongPassword), errors.Is(err, poolops.ErrWrongPassword):
		writeJSON(w, http.StatusUnauthorized, errBody(err)) // 401
	case errors.Is(err, spend.ErrUnknownPending):
		writeJSON(w, http.StatusNotFound, errBody(err)) // 404
	case errors.Is(err, spend.ErrExpiredPending):
		writeJSON(w, http.StatusGone, errBody(err)) // 410
	case errors.Is(err, spend.ErrInsufficientFunds), errors.Is(err, spend.ErrSubmitRejected),
		errors.Is(err, poolops.ErrSubmitRejected):
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
