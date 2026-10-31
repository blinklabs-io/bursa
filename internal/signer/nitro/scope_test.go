// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
)

// The enclave signs only explicit-counter opcerts. opcert-next would let the
// host re-issue an existing issue number for a new KES key, and a profiled
// request needs a binding signature the enclave does not produce. A refused
// request must not consume its nonce or advance the issue counter.
func TestServiceRefusesUnsupportedSignScope(t *testing.T) {
	for name, mutate := range map[string]func(*backend.AttestedRequest){
		"opcert-next": func(r *backend.AttestedRequest) { r.Purpose = backend.PurposeOpCertNext },
		"profile":     func(r *backend.AttestedRequest) { r.Profile = "pool@mainnet" },
	} {
		t.Run(name, func(t *testing.T) {
			service, _, _ := newTestService(t, testEvidence(t, 6))
			env := provisionTestKey(t, service)
			payload := make([]byte, 48)
			copy(payload[:32], bytes.Repeat([]byte{4}, 32))
			binary.BigEndian.PutUint64(payload[32:40], 9)
			binary.BigEndian.PutUint64(payload[40:48], 120)
			request := backend.AttestedRequest{
				Version: backend.AttestedProtocol, Purpose: backend.PurposeOpCert,
				KeyHash: backend.HashPublicKey(env.PublicKey).String(), Role: backend.KeyTypePool,
				Nonce: bytes.Repeat([]byte{7}, requestNonceSize), Payload: payload,
			}
			refused := request
			mutate(&refused)
			_, err := service.Sign(context.Background(), &refused)
			require.ErrorIs(t, err, ErrProtocol)

			signed, err := service.Sign(context.Background(), &request)
			require.NoError(t, err)
			require.True(t, ed25519.Verify(env.PublicKey, payload, signed.Signature))
		})
	}
}

func TestProxyRefusesProfiledInventory(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	handler, err := NewProxyHandler(&badSignatureEnclave{pub: publicKey, key: privateKey})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "/v1/inventory",
		strings.NewReader(`{"nonce":"","profile":"pool@mainnet"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
}
