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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
)

// healthyEnclave serves a fixed inventory on top of stateEnclave's sign.
type healthyEnclave struct{ stateEnclave }

func (e *healthyEnclave) Inventory(
	context.Context,
	[]byte,
) (backend.AttestedInventory, error) {
	return backend.AttestedInventory{Version: backend.AttestedProtocol}, nil
}

func postInventory(handler http.Handler) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/v1/inventory",
		bytes.NewReader([]byte(`{"nonce":"AAAA"}`)),
	))
	return response
}

func TestProxyInventoryReportsUnavailableAfterFailedSave(t *testing.T) {
	t.Parallel()
	enclave := &healthyEnclave{}
	saver := &recordingSaver{err: errors.New("secrets manager unavailable")}
	handler := newStateProxy(t, &enclave.stateEnclave, saver)
	handler.enclave = enclave

	require.Equal(t, http.StatusOK, postInventory(handler).Code)
	require.Equal(t, http.StatusBadGateway, postSign(handler, 5).Code)

	response := postInventory(handler)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Contains(t, response.Body.String(), "sealed counter state save failed")
	require.Contains(t, response.Body.String(), "restart")

	// a restart is a new proxy over the same enclave: healthy again
	restarted, err := NewProxyHandler(enclave, &recordingSaver{})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, postInventory(restarted).Code)
}

func TestProxyPersistsStateOnRepeatedCounter(t *testing.T) {
	t.Parallel()
	enclave, saver := &stateEnclave{}, &recordingSaver{}
	handler := newStateProxy(t, enclave, saver)
	require.Equal(t, http.StatusOK, postSign(handler, 5).Code)
	require.Equal(t, http.StatusOK, postSign(handler, 5).Code)
	require.Len(t, saver.saved, 2, "a re-sign saves its state before release")
}
