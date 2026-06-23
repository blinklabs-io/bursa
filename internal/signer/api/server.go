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
	"github.com/blinklabs-io/bursa/internal/signer/policy"
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

// KeyPolicySummary is the effective policy returned on the key-detail
// endpoint. Absent policy means the key can sign nothing (deny-by-default).
type KeyPolicySummary struct {
	AllowedRequests []string           `json:"allowed_requests"`
	Tx              *policy.TxPolicy   `json:"tx_policy,omitempty"`
	CIP8            *policy.CIP8Policy `json:"cip8_policy,omitempty"`
}

// KeyInfo describes an available key.
type KeyInfo struct {
	Hash     string            `json:"hash"`
	Type     string            `json:"type"`
	Extended bool              `json:"extended"`
	Backend  string            `json:"backend"`
	Policy   *KeyPolicySummary `json:"policy,omitempty"` // detail endpoint only
}

// Server holds the HTTP dependencies.
type Server struct {
	coord    *signer.Coordinator
	resolver *backend.Resolver
	policies *policy.Engine
	acl      *CallerACL
	validate Validator
	logger   *slog.Logger
}

// NewServer builds the API server. The logger defaults to logging.GetLogger().
func NewServer(coord *signer.Coordinator, resolver *backend.Resolver, policies *policy.Engine, acl *CallerACL, validate Validator) *Server {
	return &Server{
		coord:    coord,
		resolver: resolver,
		policies: policies,
		acl:      acl,
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
		signers := req.Signers
		var aclDenied []signer.SignerError
		if s.acl.Restricted() {
			signers = make([]string, 0, len(req.Signers))
			for _, sg := range req.Signers {
				// Must stay consistent with the coordinator's own ResolveSigner resolution.
				h, err := signer.ResolveSigner(sg)
				if err == nil && !s.acl.Allows(caller, h) {
					// Sign-path ACL denials are counted; list/get-key filtering is view filtering, not a deny event.
					s.coord.Metrics().ObserveDeny("acl")
					aclDenied = append(aclDenied, signer.SignerError{
						Signer: sg, Code: signer.CodeDenied, Reason: "caller is not authorized for this key",
					})
					continue
				}
				// Unresolvable signers fall through; the coordinator reports them.
				signers = append(signers, sg)
			}
			if len(signers) == 0 && len(aclDenied) > 0 {
				s.audit(r, caller, "tx", "denied", "audit_id", auditID, "signers", req.Signers, "reason", "caller ACL")
				writeJSON(w, http.StatusForbidden, SignTxResponse{AuditID: auditID, Errors: aclDenied})
				return
			}
		}
		res, perr, err := s.coord.SignTx(r.Context(), []byte(req.Cbor), signers)
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
		// ACL pre-filter denials are reported in the response body alongside the
		// coordinator's per-signer results, but they must NOT drive HTTP status
		// selection: an ACL denial is always 403, so prepending it would mask a
		// coordinator bad_request/not_found/backend error (e.g. report 400 as
		// 403). Keep them separate and pick status from the coordinator errors.
		allErrs := append(aclDenied, perr...)
		// If nothing signed and we have errors, surface a representative status.
		if len(res.Witnesses) == 0 && len(allErrs) > 0 {
			// Prefer the coordinator's actual signing errors; only fall back to
			// the ACL denials when there are no coordinator errors.
			primary := allErrs[0]
			if len(perr) > 0 {
				primary = perr[0]
			}
			st := codeToStatus(primary.Code)
			masked := maskSignerErrors(allErrs)
			// Log original (unmasked) reasons server-side before sending masked response.
			s.logger.Error("SignTx signer errors",
				"caller", caller,
				"audit_id", auditID,
				"tx_id", res.TxID,
				"errors", allErrs,
			)
			s.audit(r, caller, "tx", string(primary.Code), "audit_id", auditID, "tx_id", res.TxID, "signers", req.Signers, "signer_errors", len(allErrs))
			writeJSON(w, st, SignTxResponse{AuditID: auditID, TxID: res.TxID, Errors: masked})
			return
		}
		masked := maskSignerErrors(allErrs)
		if len(allErrs) > 0 {
			s.logger.Warn("SignTx partial failure", "audit_id", auditID, "errors", allErrs, "caller", caller)
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
		if s.acl.Restricted() {
			h, err := backend.ParseKeyHash(req.Key)
			if err == nil && !s.acl.Allows(caller, h) {
				s.coord.Metrics().ObserveDeny("acl")
				s.audit(r, caller, "cip8", "denied", "audit_id", auditID, "key", req.Key, "reason", "caller ACL")
				writeErr(w, http.StatusForbidden, "caller is not authorized for this key")
				return
			}
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
	caller := CallerFromContext(r.Context())
	out := make([]KeyInfo, 0, len(keys))
	for _, k := range keys {
		if !s.acl.Allows(caller, k.Hash()) {
			continue
		}
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
	if !s.acl.Allows(CallerFromContext(r.Context()), h) {
		// 404 (not 403) so restricted callers cannot probe for key existence.
		writeErr(w, http.StatusNotFound, "key not found")
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
	info := KeyInfo{Hash: ref.Hash().String(), Type: string(ref.Type()), Extended: ref.Extended(), Backend: ref.Backend()}
	if s.policies != nil {
		if p, ok := s.policies.PolicyFor(h); ok {
			// Normalize to a non-nil slice so the wire format is always an
			// array, never null.
			reqs := p.AllowedRequests
			if reqs == nil {
				reqs = []string{}
			}
			info.Policy = &KeyPolicySummary{
				AllowedRequests: reqs,
				Tx:              p.Tx,
				CIP8:            p.CIP8,
			}
		}
	}
	writeJSON(w, http.StatusOK, info)
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
