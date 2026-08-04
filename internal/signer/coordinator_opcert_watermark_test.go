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

package signer

import (
	"context"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newOpCertCoordinator(t *testing.T, k *fakeKey, wm watermark.Watermark, mode watermark.Mode) (*Coordinator, *Metrics) {
	t.Helper()
	k.typ = backend.KeyTypePool
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            k.hash.String(),
		AllowedRequests: []string{"opcert"},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	m := NewMetrics()
	return New(Deps{
		Resolver:  backend.NewResolver(fakeBackend{key: k}),
		Policy:    eng,
		Watermark: wm,
		WMMode:    mode,
		Cardano:   fakeCardano{},
		Metrics:   m,
	}), m
}

// TestSignOpCert_CounterMonotonicity_Enforce covers the core anti-double-sign
// guard: a counter must be strictly greater than the highest already signed.
func TestSignOpCert_CounterMonotonicity_Enforce(t *testing.T) {
	k := newFakeKey(t)
	c, m := newOpCertCoordinator(t, k, watermark.NewMemWatermark(), watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	// First opcert at counter 3 signs and stores 3.
	if _, code, err := c.SignOpCert(ctx, kes, 3, 100, k.hash.String()); err != nil {
		t.Fatalf("counter 3: unexpected error %v (code=%s)", err, code)
	}

	// Same counter 3 -> conflict.
	if res, code, err := c.SignOpCert(ctx, kes, 3, 101, k.hash.String()); err == nil || code != CodeConflict || res != nil {
		t.Fatalf("counter 3 repeat: want CodeConflict/nil, got (res=%v, code=%s, err=%v)", res, code, err)
	}
	// Lower counter 2 -> conflict.
	if res, code, err := c.SignOpCert(ctx, kes, 2, 102, k.hash.String()); err == nil || code != CodeConflict || res != nil {
		t.Fatalf("counter 2: want CodeConflict/nil, got (res=%v, code=%s, err=%v)", res, code, err)
	}

	// Higher counter 4 -> signs and advances.
	if res, code, err := c.SignOpCert(ctx, kes, 4, 103, k.hash.String()); err != nil || res == nil || res.SignatureHex == "" {
		t.Fatalf("counter 4: want signature, got (res=%v, code=%s, err=%v)", res, code, err)
	}
	// After advancing, counter 4 is now stale.
	if _, code, err := c.SignOpCert(ctx, kes, 4, 104, k.hash.String()); err == nil || code != CodeConflict {
		t.Fatalf("counter 4 repeat: want CodeConflict, got (code=%s, err=%v)", code, err)
	}

	// Two rejections each incremented the conflict metric (repeat-3, lower-2,
	// repeat-4 = 3 conflicts).
	if got := testutil.ToFloat64(m.watermarkConflicts); got != 3 {
		t.Fatalf("watermark_conflicts_total = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.denials.WithLabelValues(string(CodeConflict))); got != 3 {
		t.Fatalf("conflict denials = %v, want 3", got)
	}
}

// TestSignOpCert_CounterPerKeyIsolation: one cold key's counter does not gate
// another's.
func TestSignOpCert_CounterPerKeyIsolation(t *testing.T) {
	wm := watermark.NewMemWatermark()
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	kA := newFakeKey(t)
	cA, _ := newOpCertCoordinator(t, kA, wm, watermark.ModeEnforce)
	kB := newFakeKey(t)
	cB, _ := newOpCertCoordinator(t, kB, wm, watermark.ModeEnforce)

	if _, code, err := cA.SignOpCert(ctx, kes, 50, 1, kA.hash.String()); err != nil {
		t.Fatalf("keyA counter 50: %v (code=%s)", err, code)
	}
	// keyB at a much lower counter is unaffected by keyA's watermark.
	if _, code, err := cB.SignOpCert(ctx, kes, 1, 1, kB.hash.String()); err != nil {
		t.Fatalf("keyB counter 1: %v (code=%s)", err, code)
	}
}

// TestSignOpCert_CounterWarnMode: a regression is logged and metered but the
// signature is still produced.
func TestSignOpCert_CounterWarnMode(t *testing.T) {
	k := newFakeKey(t)
	c, m := newOpCertCoordinator(t, k, watermark.NewMemWatermark(), watermark.ModeWarn)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCert(ctx, kes, 9, 1, k.hash.String()); err != nil {
		t.Fatalf("counter 9: %v (code=%s)", err, code)
	}
	// Repeat counter 9: warn mode allows the signature.
	res, code, err := c.SignOpCert(ctx, kes, 9, 2, k.hash.String())
	if err != nil || res == nil || res.SignatureHex == "" {
		t.Fatalf("warn-mode repeat: want signature, got (res=%v, code=%s, err=%v)", res, code, err)
	}
	if got := testutil.ToFloat64(m.watermarkConflicts); got != 1 {
		t.Fatalf("watermark_conflicts_total = %v, want 1", got)
	}
}

// TestSignOpCert_CounterOffMode: no counter enforcement at all.
func TestSignOpCert_CounterOffMode(t *testing.T) {
	k := newFakeKey(t)
	c, m := newOpCertCoordinator(t, k, watermark.NewMemWatermark(), watermark.ModeOff)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	if _, code, err := c.SignOpCert(ctx, kes, 5, 1, k.hash.String()); err != nil {
		t.Fatalf("counter 5: %v (code=%s)", err, code)
	}
	// A stale counter still signs when the guard is off.
	if res, code, err := c.SignOpCert(ctx, kes, 5, 2, k.hash.String()); err != nil || res == nil {
		t.Fatalf("off-mode repeat: want signature, got (res=%v, code=%s, err=%v)", res, code, err)
	}
	if got := testutil.ToFloat64(m.watermarkConflicts); got != 0 {
		t.Fatalf("watermark_conflicts_total = %v, want 0", got)
	}
}
