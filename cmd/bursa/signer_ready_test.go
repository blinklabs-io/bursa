// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/stretchr/testify/require"
)

type plainBackend struct{ backend.Backend }

func (plainBackend) Name() string { return "plain" }

type probedBackend struct {
	backend.Backend
	name string
	err  error
}

func (b probedBackend) Name() string                 { return b.name }
func (b probedBackend) Health(context.Context) error { return b.err }

func TestBackendsHealthyReportsStoppedBackend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require.NoError(t, backendsHealthy(ctx, []backend.Backend{
		plainBackend{},
		probedBackend{name: "nitro-a"},
	}))

	err := backendsHealthy(ctx, []backend.Backend{
		plainBackend{},
		probedBackend{name: "nitro-a"},
		probedBackend{name: "nitro-b", err: errors.New("save failed")},
	})
	require.ErrorContains(t, err, "nitro-b")
	require.ErrorContains(t, err, "save failed")
	require.NotContains(t, err.Error(), "nitro-a")
}
