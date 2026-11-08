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
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// disconnectSaver cancels the sign request's context, as a client that went
// away mid-save does, then saves only if its own context is still live.
type disconnectSaver struct {
	recordingSaver
	disconnect context.CancelFunc
}

func (s *disconnectSaver) SaveSealedState(
	ctx context.Context,
	state []byte,
) error {
	s.disconnect()
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.recordingSaver.SaveSealedState(ctx, state)
}

func TestProxySaveOutlivesClientDisconnect(t *testing.T) {
	t.Parallel()
	enclave := &stateEnclave{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	saver := &disconnectSaver{disconnect: cancel}
	handler := newStateProxy(t, enclave, &saver.recordingSaver)
	handler.saver = saver

	postSignContext(ctx, handler, 5)
	require.Len(t, saver.saved, 1, "a client disconnect must not abort the save")
	require.Equal(t, http.StatusOK, postSign(handler, 6).Code)
}
