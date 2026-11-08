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
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
)

// stateEnclave returns a signature and a sealed state that encodes the
// request's issue counter, and counts Sign calls.
type stateEnclave struct {
	mu    sync.Mutex
	calls int
	key   ed25519.PrivateKey
	// noState releases a signature without sealed state.
	noState bool
}

func (e *stateEnclave) Challenge(context.Context) (ChallengeResponse, error) {
	return ChallengeResponse{}, errors.New("unused")
}

func (e *stateEnclave) Inventory(
	context.Context,
	[]byte,
) (backend.AttestedInventory, error) {
	return backend.AttestedInventory{}, errors.New("unused")
}

func (e *stateEnclave) signCalls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func (e *stateEnclave) Sign(
	_ context.Context,
	request backend.AttestedRequest,
) (SignResponse, error) {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	response := SignResponse{AttestedResponse: backend.AttestedResponse{
		Version:   backend.AttestedProtocol,
		Nonce:     request.Nonce,
		Signature: ed25519.Sign(e.key, request.Payload),
	}}
	if !e.noState {
		response.SealedState = bytes.Clone(request.Payload[32:40])
	}
	return response, nil
}

// recordingSaver keeps the last saved state. The first save blocks on
// release when gate is set.
type recordingSaver struct {
	mu      sync.Mutex
	saved   [][]byte
	err     error
	gate    chan struct{}
	started chan struct{}
	first   sync.Once
}

func (s *recordingSaver) SaveSealedState(
	_ context.Context,
	state []byte,
) error {
	s.first.Do(func() {
		if s.started != nil {
			close(s.started)
		}
		if s.gate != nil {
			<-s.gate
		}
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.saved = append(s.saved, bytes.Clone(state))
	return nil
}

func (s *recordingSaver) last() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.saved) == 0 {
		return nil
	}
	return s.saved[len(s.saved)-1]
}

// lastCounter decodes the issue counter of the last saved state.
func lastCounter(t *testing.T, s *recordingSaver) uint64 {
	t.Helper()
	state := s.last()
	require.Len(t, state, 8, "no sealed state was saved")
	return binary.BigEndian.Uint64(state)
}

func postSign(
	handler http.Handler,
	counter uint64,
) *httptest.ResponseRecorder {
	payload := make([]byte, 48)
	binary.BigEndian.PutUint64(payload[32:40], counter)
	body, err := json.Marshal(backend.AttestedRequest{
		Version: backend.AttestedProtocol, Purpose: backend.PurposeOpCert,
		Role: backend.KeyTypePool, Payload: payload,
		Nonce: bytes.Repeat([]byte{1}, requestNonceSize),
	})
	if err != nil {
		panic(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body)),
	)
	return response
}

func newStateProxy(
	t *testing.T,
	enclave *stateEnclave,
	saver *recordingSaver,
) *ProxyHandler {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	enclave.key = key
	handler, err := NewProxyHandler(enclave, saver)
	require.NoError(t, err)
	return handler
}

func TestProxyPersistsStateBeforeReleasingSignature(t *testing.T) {
	t.Parallel()
	enclave, saver := &stateEnclave{}, &recordingSaver{}
	handler := newStateProxy(t, enclave, saver)
	response := postSign(handler, 5)
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, uint64(5), lastCounter(t, saver))
	// the signer never sees the sealed state
	require.NotContains(t, response.Body.String(), "sealed_state")
	var released backend.AttestedResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &released))
	require.NotEmpty(t, released.Signature)
}

func TestProxyFailedSaveReleasesNoSignature(t *testing.T) {
	t.Parallel()
	enclave := &stateEnclave{}
	saver := &recordingSaver{err: errors.New("secrets manager unavailable")}
	handler := newStateProxy(t, enclave, saver)
	response := postSign(handler, 5)
	require.Equal(t, http.StatusBadGateway, response.Code)
	require.NotContains(t, response.Body.String(), "signature")
	require.Equal(t, 1, enclave.signCalls())
}

func TestProxyRefusesSignatureWithoutSealedState(t *testing.T) {
	t.Parallel()
	enclave, saver := &stateEnclave{noState: true}, &recordingSaver{}
	handler := newStateProxy(t, enclave, saver)
	response := postSign(handler, 5)
	require.Equal(t, http.StatusBadGateway, response.Code)
	require.NotContains(t, response.Body.String(), "signature")
	require.Nil(t, saver.last())
}

func TestProxySerializesSignAndSave(t *testing.T) {
	t.Parallel()
	enclave := &stateEnclave{}
	saver := &recordingSaver{
		gate:    make(chan struct{}),
		started: make(chan struct{}),
	}
	handler := newStateProxy(t, enclave, saver)
	var release sync.Once
	releaseSave := func() { release.Do(func() { close(saver.gate) }) }
	defer releaseSave()

	codes := make(chan int, 2)
	go func() { codes <- postSign(handler, 5).Code }()
	select {
	case <-saver.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first save never started: signature released before persisting")
	}
	go func() { codes <- postSign(handler, 6).Code }()
	// while the first save is pending, no second enclave Sign may run
	require.Never(t, func() bool {
		return enclave.signCalls() > 1
	}, 300*time.Millisecond, 10*time.Millisecond,
		"second sign reached the enclave before the first state was saved")
	releaseSave()
	for range 2 {
		select {
		case code := <-codes:
			require.Equal(t, http.StatusOK, code)
		case <-time.After(5 * time.Second):
			t.Fatal("sign request never completed")
		}
	}
	require.Equal(t, uint64(6), lastCounter(t, saver))
	require.Len(t, saver.saved, 2)
}
