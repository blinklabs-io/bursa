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
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/blinklabs-io/bursa/internal/logging"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/google/uuid"
)

// SignRequest is the POST /v1/sign body.
type SignRequest struct {
	Type    string   `json:"type"`    // "tx" | "cip8"
	Cbor    string   `json:"cbor"`    // tx: hex CBOR or JSON envelope
	Signers []string `json:"signers"` // tx: key hashes / addresses
	Payload string   `json:"payload"` // cip8: hex
	Address string   `json:"address"` // cip8: bech32
	Key     string   `json:"key"`     // cip8: key hash
}

// SignTxResponse is returned for type=tx.
type SignTxResponse struct {
	AuditID   string               `json:"audit_id"`
	TxID      string               `json:"tx_id"`
	Witnesses []string             `json:"witnesses,omitempty"`
	SignedTx  string               `json:"signed_tx,omitempty"`
	Errors    []signer.SignerError `json:"errors,omitempty"`
}

// SignCIP8Response is returned for type=cip8.
type SignCIP8Response struct {
	AuditID   string `json:"audit_id"`
	Signature string `json:"signature"`
	Key       string `json:"key"`
}

// KeyInfo describes an available key.
type KeyInfo struct {
	Hash     string `json:"hash"`
	Type     string `json:"type"`
	Extended bool   `json:"extended"`
	Backend  string `json:"backend"`
}

// Server holds the HTTP dependencies.
type Server struct {
	coord    *signer.Coordinator
	resolver *backend.Resolver
	validate Validator
	logger   *slog.Logger
}

// NewServer builds the API server. The logger defaults to logging.GetLogger().
func NewServer(coord *signer.Coordinator, resolver *backend.Resolver, validate Validator) *Server {
	return &Server{
		coord:    coord,
		resolver: resolver,
		validate: validate,
		logger:   logging.GetLogger(),
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func codeToStatus(c signer.ErrorCode) int {
	switch c {
	case signer.CodeBadRequest:
		return http.StatusBadRequest
	case signer.CodeNotFound:
		return http.StatusNotFound
	case signer.CodeDenied:
		return http.StatusForbidden
	case signer.CodeConflict:
		return http.StatusConflict
	case signer.CodeUnsupported:
		return http.StatusUnprocessableEntity
	case signer.CodeBackend:
		return http.StatusBadGateway
	case signer.CodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	// Generate a per-request audit ID so every log line and response body for
	// this request share a single correlation identifier.
	auditID := uuid.New().String()
	caller := CallerFromContext(r.Context())
	if r.Method != http.MethodPost {
		s.audit(r, caller, "", "method_not_allowed", "audit_id", auditID)
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Fix 1: limit request body to 1 MB before decoding.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			s.audit(r, caller, "", "request_entity_too_large", "audit_id", auditID, "error", err.Error())
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		s.audit(r, caller, "", "bad_request", "audit_id", auditID, "error", err.Error())
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	switch req.Type {
	case "tx":
		res, perr, err := s.coord.SignTx(r.Context(), []byte(req.Cbor), req.Signers)
		if err != nil {
			if signer.IsBadRequest(err) {
				s.audit(r, caller, "tx", "bad_request", "audit_id", auditID, "signers", req.Signers, "error", err.Error())
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			// Fix 3: mask 5xx bodies; log real error server-side.
			s.logger.Error("SignTx internal error",
				"caller", caller,
				"audit_id", auditID,
				"error", err,
			)
			s.audit(r, caller, "tx", "error", "audit_id", auditID, "signers", req.Signers)
			writeErr(w, http.StatusInternalServerError, "internal server error")
			return
		}
		// If nothing signed and we have errors, surface the first error's status.
		if len(res.Witnesses) == 0 && len(perr) > 0 {
			st := codeToStatus(perr[0].Code)
			masked := maskSignerErrors(perr)
			// Log original (unmasked) reasons server-side before sending masked response.
			s.logger.Error("SignTx signer errors",
				"caller", caller,
				"audit_id", auditID,
				"tx_id", res.TxID,
				"errors", perr,
			)
			s.audit(r, caller, "tx", string(perr[0].Code), "audit_id", auditID, "tx_id", res.TxID, "signers", req.Signers, "signer_errors", len(perr))
			writeJSON(w, st, SignTxResponse{AuditID: auditID, TxID: res.TxID, Errors: masked})
			return
		}
		masked := maskSignerErrors(perr)
		if len(perr) > 0 {
			s.logger.Warn("SignTx partial failure", "audit_id", auditID, "errors", perr, "caller", caller)
		}
		resp := SignTxResponse{AuditID: auditID, TxID: res.TxID, Errors: masked}
		for _, wit := range res.Witnesses {
			resp.Witnesses = append(resp.Witnesses, hex.EncodeToString(wit))
		}
		if len(res.SignedTx) > 0 {
			resp.SignedTx = hex.EncodeToString(res.SignedTx)
		}
		s.audit(r, caller, "tx", "signed",
			"audit_id", auditID,
			"tx_id", res.TxID,
			"witnesses", len(resp.Witnesses),
			"signer_errors", len(perr),
			"signers", req.Signers,
		)
		writeJSON(w, http.StatusOK, resp)
	case "cip8":
		payload, err := hex.DecodeString(req.Payload)
		if err != nil {
			s.audit(r, caller, "cip8", "bad_request", "audit_id", auditID, "key", req.Key, "address", req.Address)
			writeErr(w, http.StatusBadRequest, "invalid payload hex")
			return
		}
		res, code, err := s.coord.SignCIP8(r.Context(), payload, req.Address, req.Key)
		if err != nil {
			st := codeToStatus(code)
			if st >= 500 {
				// Fix 3: mask 5xx bodies.
				s.logger.Error("SignCIP8 error",
					"caller", caller,
					"audit_id", auditID,
					"code", code,
					"error", err,
				)
				s.audit(r, caller, "cip8", "error", "audit_id", auditID, "key", req.Key, "address", req.Address)
				if st == http.StatusBadGateway {
					writeErr(w, st, "backend error")
				} else {
					writeErr(w, st, "internal server error")
				}
				return
			}
			s.audit(r, caller, "cip8", string(code), "audit_id", auditID, "key", req.Key, "address", req.Address, "error", err.Error())
			writeErr(w, st, err.Error())
			return
		}
		s.audit(r, caller, "cip8", "signed", "audit_id", auditID, "key", req.Key, "address", req.Address)
		writeJSON(w, http.StatusOK, SignCIP8Response{AuditID: auditID, Signature: res.SignatureHex, Key: res.KeyHex})
	default:
		s.audit(r, caller, req.Type, "bad_request", "audit_id", auditID)
		writeErr(w, http.StatusBadRequest, "unknown request type")
	}
}

// audit emits a structured sign-request audit log line. Every outcome on every
// code path must call this exactly once. attrs must be key-value pairs (slog style).
// No secrets or raw CBOR are included.
func (s *Server) audit(r *http.Request, caller, reqType, outcome string, attrs ...any) {
	args := make([]any, 0, 8+len(attrs))
	args = append(args,
		"caller", caller,
		"type", reqType,
		"outcome", outcome,
		"remote_addr", r.RemoteAddr,
	)
	args = append(args, attrs...)
	s.logger.Info("sign request", args...)
}

// maskSignerErrors applies per-entry masking: 5xx signer errors have their Reason
// replaced with a generic message; 4xx errors (denied, not_found, etc.) are
// returned with their original Reason intact (design §13).
func maskSignerErrors(errs []signer.SignerError) []signer.SignerError {
	out := make([]signer.SignerError, len(errs))
	for i, e := range errs {
		out[i] = e
		if codeToStatus(e.Code) >= 500 {
			out[i].Reason = "backend error"
		}
	}
	return out
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.resolver.ListKeys(r.Context())
	if err != nil {
		// Fix 3: mask 5xx.
		s.logger.Error("ListKeys error", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal server error")
		return
	}
	out := make([]KeyInfo, 0, len(keys))
	for _, k := range keys {
		out = append(out, KeyInfo{Hash: k.Hash().String(), Type: string(k.Type()), Extended: k.Extended(), Backend: k.Backend()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	hashStr := r.PathValue("hash")
	h, err := backend.ParseKeyHash(hashStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid key hash")
		return
	}
	ref, err := s.resolver.Resolve(r.Context(), h)
	if errors.Is(err, backend.ErrKeyNotFound) {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	if err != nil {
		// Fix 3: mask 5xx.
		s.logger.Error("Resolve key error", "hash", hashStr, "error", err)
		writeErr(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, KeyInfo{Hash: ref.Hash().String(), Type: string(ref.Type()), Extended: ref.Extended(), Backend: ref.Backend()})
}

// Handler returns the authenticated mux for the signer API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Fix 5: use method-qualified pattern so Go's router emits 405+Allow automatically.
	mux.HandleFunc("POST /v1/sign", s.handleSign)
	mux.HandleFunc("GET /v1/keys", s.handleListKeys)
	mux.HandleFunc("GET /v1/keys/{hash}", s.handleGetKey)
	return JWTMiddleware(s.validate, mux)
}

// HealthHandler returns the unauthenticated health/metrics mux.
func HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}
