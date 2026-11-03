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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
)

func TestRPCProvisionReloadAndSign(t *testing.T) {
	service, _, _ := newTestService(t, testEvidence(t, 6))
	client, _ := testRPCClient(t, service)
	provisioned, err := client.Provision(context.Background(), testProvisionRequest())
	require.NoError(t, err)
	loaded, err := client.Reload(context.Background(), ReloadRequest{
		Version: Protocol, Region: "us-east-1", Credentials: testCredentials,
		Envelope: provisioned.Envelope,
	})
	require.NoError(t, err)
	require.Equal(t, provisioned.Envelope.PublicKey, loaded.PublicKey)
	payload := make([]byte, 48)
	payload[39] = 1
	response, err := client.Sign(context.Background(), backend.AttestedRequest{
		Version: backend.AttestedProtocol, Purpose: backend.PurposeOpCert,
		KeyHash: backend.HashPublicKey(loaded.PublicKey).String(), Role: backend.KeyTypePool,
		Nonce: bytes.Repeat([]byte{1}, 32), Payload: payload,
	})
	require.NoError(t, err)
	require.True(t, ed25519.Verify(loaded.PublicKey, payload, response.Signature))
}

func TestRPCRejectsUnknownFields(t *testing.T) {
	service, _, _ := newTestService(t, testEvidence(t, 7))
	_, conn := testRPCClient(t, service)
	var response ReloadResponse
	err := conn.Invoke(context.Background(), "/"+rpcServiceName+"/Reload", map[string]any{
		"version": Protocol,
		"unknown": true,
	}, &response)
	require.Error(t, err)
}

type acceptVerifier struct{}

func (acceptVerifier) Verify(context.Context, []byte, []byte) error { return nil }

type badSignatureEnclave struct {
	pub ed25519.PublicKey
	key ed25519.PrivateKey
}

func (e *badSignatureEnclave) Inventory(context.Context, []byte) (backend.AttestedInventory, error) {
	return backend.AttestedInventory{
		Version:     backend.AttestedProtocol,
		Keys:        []backend.AttestedKeyInfo{{Role: backend.KeyTypePool, PublicKey: e.pub}},
		Attestation: []byte{1},
	}, nil
}

func (e *badSignatureEnclave) Sign(_ context.Context, request backend.AttestedRequest) (backend.AttestedResponse, error) {
	return backend.AttestedResponse{
		Version:   backend.AttestedProtocol,
		Nonce:     request.Nonce,
		Signature: ed25519.Sign(e.key, request.Payload),
	}, nil
}

func TestProxySignatureMismatchFailsAtKeyRef(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	custody := backend.NewAttestedBackend(
		"nitro",
		&badSignatureEnclave{pub: publicKey, key: wrongKey},
		acceptVerifier{},
	)
	require.NoError(t, custody.Load(context.Background()))
	ref, err := custody.GetKey(context.Background(), backend.HashPublicKey(publicKey))
	require.NoError(t, err)
	payload := make([]byte, 48)
	_, err = backend.SignFor(context.Background(), ref, backend.PurposeOpCert, payload)
	require.ErrorIs(t, err, backend.ErrInvalidSignature)
}

func TestProxyRejectsMalformedRequests(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	handler, err := NewProxyHandler(&badSignatureEnclave{pub: publicKey, key: privateKey})
	require.NoError(t, err)
	for name, body := range map[string]string{
		"unknown field": `{"nonce":"","extra":true}`,
		"trailing JSON": `{"nonce":""}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/inventory", strings.NewReader(body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			require.Equal(t, http.StatusBadRequest, response.Code)
		})
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/inventory", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
}

func TestStrictJSONCodecRejectsTrailingData(t *testing.T) {
	var request ReloadRequest
	err := nitroCodec.Unmarshal([]byte(`{"version":"`+Protocol+`"}{}`), &request)
	require.True(t, errors.Is(err, ErrProtocol))
}
