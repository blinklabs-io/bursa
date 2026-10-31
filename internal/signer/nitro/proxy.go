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

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

const maxProxyBody = 1 << 20

type enclaveAPI interface {
	Inventory(context.Context, []byte) (backend.AttestedInventory, error)
	Sign(context.Context, backend.AttestedRequest) (backend.AttestedResponse, error)
}

// ProxyHandler translates the existing attested-signer HTTP contract to the
// enclave's gRPC protocol. It never handles private or data-key plaintext.
type ProxyHandler struct {
	enclave enclaveAPI
}

// NewProxyHandler constructs the host-side signer proxy.
func NewProxyHandler(enclave enclaveAPI) (*ProxyHandler, error) {
	if enclave == nil {
		return nil, errors.New("nitro enclave client is required")
	}
	return &ProxyHandler{enclave: enclave}, nil
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

// ServeHTTP exposes only the two paths consumed by backend.HTTPEnclave.
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
			http.Error(w, "enclave inventory unavailable", http.StatusBadGateway)
			return
		}
		writeJSON(w, response)
	case "/v1/sign":
		var request backend.AttestedRequest
		if err := decodeRequest(w, r, &request); err != nil {
			http.Error(w, "invalid sign request", http.StatusBadRequest)
			return
		}
		response, err := p.enclave.Sign(r.Context(), request)
		if err != nil {
			http.Error(w, "enclave sign unavailable", http.StatusBadGateway)
			return
		}
		writeJSON(w, response)
	default:
		http.NotFound(w, r)
	}
}
