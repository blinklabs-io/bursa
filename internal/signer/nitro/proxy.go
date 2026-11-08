// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const maxProxyBody = 1 << 20

type enclaveAPI interface {
	Inventory(context.Context, []byte) (backend.AttestedInventory, error)
	Challenge(context.Context) (ChallengeResponse, error)
	Sign(
		context.Context,
		backend.AttestedRequest,
	) (SignResponse, error)
}

// sealedStateSaver durably persists the sealed counter state.
type sealedStateSaver interface {
	SaveSealedState(context.Context, []byte) error
}

// ProxyHandler translates the existing attested-signer HTTP contract to the
// enclave's gRPC protocol. It never handles private or data-key plaintext.
type ProxyHandler struct {
	enclave enclaveAPI
	saver   sealedStateSaver
	// signMu is held across the enclave Sign and the save of its sealed
	// state. Without it, concurrent requests could store a lower counter's
	// state after a higher one was already released.
	signMu sync.Mutex
}

// NewProxyHandler constructs the host-side signer proxy.
func NewProxyHandler(
	enclave enclaveAPI,
	saver sealedStateSaver,
) (*ProxyHandler, error) {
	if enclave == nil || saver == nil {
		return nil, errors.New(
			"nitro enclave client and sealed state store are required",
		)
	}
	return &ProxyHandler{enclave: enclave, saver: saver}, nil
}

func decodeRequest(w http.ResponseWriter, r *http.Request, out any) error {
	if r.Method != http.MethodPost {
		return errors.New("method must be POST")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxProxyBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing request data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(http.ErrAbortHandler)
	}
}

// signAndPersist signs and durably stores the returned sealed state before
// releasing the signature. A failed save, or a response without state, fails
// the request and releases nothing. The running enclave has still counted
// the issue number and refuses it until a restart reloads the stored state,
// which predates this request.
//
// The sealed state lives in one secret. Replicas pointed at the same secret
// would overwrite each other's state (last writer wins, no compare-and-swap),
// so it does not coordinate them: the signer's shared watermark remains the
// cross-replica authority. The host can also roll the secret back, so it
// narrows the restart gap and does not replace the watermark.
func (p *ProxyHandler) signAndPersist(
	ctx context.Context,
	request backend.AttestedRequest,
) (backend.AttestedResponse, error) {
	p.signMu.Lock()
	defer p.signMu.Unlock()
	response, err := p.enclave.Sign(ctx, request)
	if err != nil {
		return backend.AttestedResponse{}, err
	}
	if len(response.SealedState) == 0 {
		return backend.AttestedResponse{}, errors.New(
			"enclave returned no sealed counter state",
		)
	}
	if err := p.saver.SaveSealedState(ctx, response.SealedState); err != nil {
		return backend.AttestedResponse{}, err
	}
	return response.AttestedResponse, nil
}

// ServeHTTP exposes only the paths consumed by backend.HTTPEnclave.
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/inventory":
		var request struct {
			Nonce []byte `json:"nonce"`
		}
		if err := decodeRequest(w, r, &request); err != nil {
			http.Error(w, "invalid inventory request", http.StatusBadRequest)
			return
		}
		response, err := p.enclave.Inventory(r.Context(), request.Nonce)
		if err != nil {
			http.Error(
				w,
				"enclave inventory unavailable",
				http.StatusBadGateway,
			)
			return
		}
		writeJSON(w, response)
	case "/v1/challenge":
		var request struct{}
		if err := decodeRequest(w, r, &request); err != nil {
			http.Error(w, "invalid challenge request", http.StatusBadRequest)
			return
		}
		response, err := p.enclave.Challenge(r.Context())
		if err != nil {
			http.Error(
				w,
				"enclave challenge unavailable",
				http.StatusBadGateway,
			)
			return
		}
		writeJSON(w, response)
	case "/v1/sign":
		var request backend.AttestedRequest
		if err := decodeRequest(w, r, &request); err != nil {
			http.Error(w, "invalid sign request", http.StatusBadRequest)
			return
		}
		response, err := p.signAndPersist(r.Context(), request)
		if err != nil {
			http.Error(w, "enclave sign unavailable", http.StatusBadGateway)
			return
		}
		writeJSON(w, response)
	default:
		http.NotFound(w, r)
	}
}
