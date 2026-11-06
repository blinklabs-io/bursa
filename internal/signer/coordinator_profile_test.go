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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// profiledFakeKey is a fakeKey served by a named backend under a profile.
type profiledFakeKey struct {
	*fakeKey
	backend string
	profile string
}

func (k profiledFakeKey) Backend() string { return k.backend }
func (k profiledFakeKey) Profile() string { return k.profile }

// profiledFakeBackend holds one shared key; an empty profile makes it an
// unprofiled backend.
type profiledFakeBackend struct {
	name    string
	profile string
	key     *fakeKey
}

func (b profiledFakeBackend) Name() string    { return b.name }
func (b profiledFakeBackend) Profile() string { return b.profile }
func (b profiledFakeBackend) ref() backend.KeyRef {
	if b.profile == "" {
		return b.key
	}
	return profiledFakeKey{fakeKey: b.key, backend: b.name, profile: b.profile}
}
func (b profiledFakeBackend) ListKeys(context.Context) ([]backend.KeyRef, error) {
	return []backend.KeyRef{b.ref()}, nil
}
func (b profiledFakeBackend) GetKey(_ context.Context, h backend.KeyHash) (backend.KeyRef, error) {
	if h == b.key.hash {
		return b.ref(), nil
	}
	return nil, backend.ErrKeyNotFound
}

func newProfiledCoordinator(t *testing.T, k *fakeKey, backends ...profiledFakeBackend) (*Coordinator, *watermark.MemWatermark) {
	t.Helper()
	k.typ = backend.KeyTypePool
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            k.hash.String(),
		AllowedRequests: []string{"opcert", "tx", "cip8"},
		Tx:              &policy.TxPolicy{},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bs := make([]backend.Backend, len(backends))
	for i, b := range backends {
		bs[i] = b
	}
	wm := watermark.NewMemWatermark()
	return New(Deps{
		Resolver:  backend.NewResolver(bs...),
		Policy:    eng,
		Watermark: wm,
		WMMode:    watermark.ModeEnforce,
		Cardano: fakeCardano{
			insp: &bursa.TxInspection{TxId: "abc", TTL: 10},
			txid: make([]byte, 32),
		},
		Metrics: NewMetrics(),
	}), wm
}

const (
	profPreview = "otg@preview"
	profMusashi = "otg@musashi"
)

// Two profiled backends holding one cold key keep independent opcert counter
// histories: the preview chain floor does not refuse the musashi chain counter.
func TestProfiledOpCert_IndependentHistories(t *testing.T) {
	t.Parallel()
	k := newFakeKey(t)
	c, _ := newProfiledCoordinator(t, k,
		profiledFakeBackend{"dev-preview", profPreview, k},
		profiledFakeBackend{"dev-musashi", profMusashi, k})
	kes := make([]byte, kesVkeySize)
	id := k.hash.String()
	preview := WithProfile(context.Background(), profPreview)
	musashi := WithProfile(context.Background(), profMusashi)

	res, code, err := c.SignOpCertFromChain(preview, kes, 6, 1, id)
	if err != nil || res.IssueCounter != 7 {
		t.Fatalf("preview chain 6: res=%v code=%s err=%v", res, code, err)
	}
	// musashi has no history: chain 0 is accepted, issuing counter 1.
	res, code, err = c.SignOpCertFromChain(musashi, kes, 0, 1, id)
	if err != nil || res.IssueCounter != 1 {
		t.Fatalf("musashi chain 0: res=%v code=%s err=%v", res, code, err)
	}
	// each history is still enforced on its own profile
	if _, code, err = c.SignOpCertFromChain(preview, kes, 0, 1, id); err == nil || code != CodeConflict {
		t.Fatalf("preview chain 0 after 6: want conflict, got code=%s err=%v", code, err)
	}
	// legacy issue counter form: independent per profile too
	if _, code, err = c.SignOpCert(musashi, kes, 2, 1, id); err != nil {
		t.Fatalf("musashi issue 2: code=%s err=%v", code, err)
	}
	if _, code, err = c.SignOpCert(preview, kes, 8, 1, id); err != nil {
		t.Fatalf("preview issue 8: code=%s err=%v", code, err)
	}
	if _, code, err = c.SignOpCert(musashi, kes, 2, 1, id); err == nil || code != CodeConflict {
		t.Fatalf("musashi issue 2 repeat: want conflict, got code=%s err=%v", code, err)
	}
}

// An unprofiled backend keeps the record scopes it had before profile routing,
// and a profiled one appends "|<profile>" to every scope.
func TestProfiledRecordScopes(t *testing.T) {
	t.Parallel()
	txScope := "tx:" + strings.Repeat("00", 32)
	cases := []struct {
		name    string
		profile string
		suffix  string
	}{
		{"unprofiled", "", ""},
		{"profiled", profPreview, "|" + profPreview},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k := newFakeKey(t)
			c, wm := newProfiledCoordinator(t, k, profiledFakeBackend{"dev", tc.profile, k})
			ctx := context.Background()
			kes := make([]byte, kesVkeySize)
			id := k.hash.String()

			if _, code, err := c.SignOpCertFromChain(ctx, kes, 4, 1, id); err != nil {
				t.Fatalf("chain form: code=%s err=%v", code, err)
			}
			if _, code, err := c.SignOpCert(ctx, kes, 9, 1, id); err != nil {
				t.Fatalf("issue form: code=%s err=%v", code, err)
			}
			if res, perr, err := c.SignTx(ctx, []byte(testTxCbor), testTxEra, []string{id}); err != nil || len(perr) != 0 || len(res.Witnesses) != 1 {
				t.Fatalf("tx: res=%v perr=%v err=%v", res, perr, err)
			}

			wantCounters := map[string]uint64{
				"opcert-chain-floor" + tc.suffix:  4,
				"opcert-chain-issued" + tc.suffix: 9,
				"opcert-counter" + tc.suffix:      9,
			}
			for scope, want := range wantCounters {
				got, ok, err := wm.CounterFor(ctx, k.hash, scope)
				if err != nil || !ok || got != want {
					t.Errorf("counter scope %q: got %d ok=%v err=%v, want %d", scope, got, ok, err, want)
				}
			}
			// a differing payload conflicts only where a tx record was written
			if err := wm.Check(ctx, k.hash, txScope+tc.suffix, []byte("other")); !errors.Is(err, watermark.ErrConflict) {
				t.Errorf("tx record scope %q: want ErrConflict, got %v", txScope+tc.suffix, err)
			}
			if tc.suffix != "" {
				for _, scope := range []string{"opcert-chain-floor", "opcert-chain-issued", "opcert-counter"} {
					if _, ok, _ := wm.CounterFor(ctx, k.hash, scope); ok {
						t.Errorf("profiled key wrote the unprofiled counter scope %q", scope)
					}
				}
				if err := wm.Check(ctx, k.hash, txScope, []byte("other")); err != nil {
					t.Errorf("profiled key wrote the unprofiled tx scope: %v", err)
				}
			}
		})
	}
}

// Routing failures reach the caller before any custody or record is touched.
func TestProfiledRouting_Coordinator(t *testing.T) {
	t.Parallel()
	k := newFakeKey(t)
	c, wm := newProfiledCoordinator(t, k,
		profiledFakeBackend{"dev-preview", profPreview, k},
		profiledFakeBackend{"dev-musashi", profMusashi, k})
	kes := make([]byte, kesVkeySize)
	id := k.hash.String()
	ctx := context.Background()

	t.Run("opcert without profile", func(t *testing.T) {
		_, code, err := c.SignOpCertFromChain(ctx, kes, 1, 1, id)
		if code != CodeBadRequest || !errors.Is(err, backend.ErrProfileRequired) {
			t.Fatalf("code=%s err=%v", code, err)
		}
	})
	t.Run("opcert unknown profile", func(t *testing.T) {
		_, code, err := c.SignOpCert(WithProfile(ctx, "otg@preprod"), kes, 1, 1, id)
		if code != CodeNotFound || err == nil {
			t.Fatalf("code=%s err=%v", code, err)
		}
	})
	t.Run("cip8 without profile", func(t *testing.T) {
		_, code, err := c.SignCIP8(ctx, []byte("x"), "addr", id)
		if code != CodeBadRequest || !errors.Is(err, backend.ErrProfileRequired) {
			t.Fatalf("code=%s err=%v", code, err)
		}
	})
	t.Run("tx without profile", func(t *testing.T) {
		_, perr, err := c.SignTx(ctx, []byte(testTxCbor), testTxEra, []string{id})
		if err != nil || len(perr) != 1 || perr[0].Code != CodeBadRequest {
			t.Fatalf("perr=%+v err=%v", perr, err)
		}
	})
	t.Run("tx unknown profile", func(t *testing.T) {
		_, perr, err := c.SignTx(WithProfile(ctx, "otg@preprod"), []byte(testTxCbor), testTxEra, []string{id})
		if err != nil || len(perr) != 1 || perr[0].Code != CodeNotFound {
			t.Fatalf("perr=%+v err=%v", perr, err)
		}
	})
	t.Run("nothing recorded", func(t *testing.T) {
		for _, scope := range []string{"opcert-chain-floor", "opcert-chain-issued", "opcert-counter"} {
			for _, suffix := range []string{"", "|" + profPreview, "|" + profMusashi} {
				if _, ok, err := wm.CounterFor(ctx, k.hash, scope+suffix); err != nil || ok {
					t.Errorf("refused request recorded scope %q: ok=%v err=%v", scope+suffix, ok, err)
				}
			}
		}
	})
}

// A key held only by an unprofiled backend is not network scoped, so a tx
// that names a profile for its armory signer still gets that key's witness.
func TestProfiledRouting_UnprofiledSignerIgnoresProfile(t *testing.T) {
	t.Parallel()
	k := newFakeKey(t)
	c, _ := newProfiledCoordinator(t, k, profiledFakeBackend{"plain", "", k})
	res, perr, err := c.SignTx(WithProfile(context.Background(), profPreview), []byte(testTxCbor), testTxEra, []string{k.hash.String()})
	if err != nil || len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("res=%+v perr=%+v err=%v", res, perr, err)
	}
}

// Under a profile, the issued record's scope carries the profile, and a commit
// refused at it is still reported as an issued-record conflict.
func TestProfiledOpCert_ConcurrentIssuedConflict(t *testing.T) {
	t.Parallel()
	k := newFakeKey(t)
	k.typ = backend.KeyTypePool
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            k.hash.String(),
		AllowedRequests: []string{"opcert"},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	pw := &pausingCounterWatermark{
		Watermark: watermark.NewMemWatermark(),
		counter:   watermark.NewMemWatermark(),
		paused:    make(chan struct{}),
		release:   make(chan struct{}),
	}
	c := New(Deps{
		Resolver: backend.NewResolver(
			profiledFakeBackend{"dev-preview", profPreview, k},
		),
		Policy:    eng,
		Watermark: pw,
		WMMode:    watermark.ModeEnforce,
		Metrics:   NewMetrics(),
	})
	ctx := WithProfile(context.Background(), profPreview)
	kes := make([]byte, kesVkeySize)

	res, code, err := raceOpCert(
		t,
		pw,
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCertFromChain(ctx, kes, 20, 100, k.hash.String())
		},
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCert(ctx, kes, 5, 101, k.hash.String())
		},
	)
	if code != CodeConflict || res != nil || err == nil ||
		!strings.Contains(err.Error(), "issued concurrently") {
		t.Fatalf(
			"chain 20 racing issue 5 under a profile: res=%v code=%s err=%v, want an issued-record conflict",
			res,
			code,
			err,
		)
	}
	floor := opcertChainFloorScope + "|" + profPreview
	if v, ok, _ := pw.counter.CounterFor(context.Background(), k.hash, floor); ok {
		t.Fatalf("profiled floor = %d after a refused request, want none", v)
	}
}

// lockedBuffer serialises writes from a JSON slog handler.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// signLogs decodes every "sign" log line written to b.
func (b *lockedBuffer) signLogs(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b.buf.Bytes()), []byte("\n")) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		if m["msg"] == "sign" {
			out = append(out, m)
		}
	}
	return out
}

// Sign decisions about a key served by a profiled backend name that backend
// and the profile whose records were consulted, so two profiles holding one
// cold key are told apart in the logs.
func TestProfiledSignLogs_NameBackendAndProfile(t *testing.T) {
	t.Parallel()
	k := newFakeKey(t)
	c, _ := newProfiledCoordinator(t, k,
		profiledFakeBackend{"dev-preview", profPreview, k},
		profiledFakeBackend{"dev-musashi", profMusashi, k})
	buf := &lockedBuffer{}
	c.deps.Logger = slog.New(slog.NewJSONHandler(buf, nil))
	kes := make([]byte, kesVkeySize)
	id := k.hash.String()
	musashi := WithProfile(context.Background(), profMusashi)

	if _, code, err := c.SignOpCertFromChain(musashi, kes, 3, 1, id); err != nil {
		t.Fatalf("musashi chain 3: code=%s err=%v", code, err)
	}
	if _, code, err := c.SignOpCertFromChain(musashi, kes, 1, 1, id); code != CodeConflict {
		t.Fatalf("musashi chain 1 after 3: want conflict, got code=%s err=%v", code, err)
	}
	if res, perr, err := c.SignTx(musashi, []byte(testTxCbor), testTxEra, []string{id}); err != nil || len(perr) != 0 || len(res.Witnesses) != 1 {
		t.Fatalf("tx: res=%v perr=%v err=%v", res, perr, err)
	}
	// the fake key cannot sign CIP-8; the refusal is still a logged decision
	if _, code, _ := c.SignCIP8(musashi, []byte("x"), "", id); code != CodeUnsupported {
		t.Fatalf("cip8: want unsupported, got code=%s", code)
	}

	logs := buf.signLogs(t)
	if len(logs) != 4 {
		t.Fatalf("want 4 sign log lines, got %d: %v", len(logs), logs)
	}
	for _, m := range logs {
		if m["backend"] != "dev-musashi" || m["profile"] != profMusashi {
			t.Errorf("sign log %v: want backend dev-musashi and profile %s", m, profMusashi)
		}
	}
}

// seedLegacyOpCert writes the unscoped opcert records a key had before
// profile scoping: issued counter issued, chain floor floor.
func seedLegacyOpCert(t *testing.T, wm *watermark.MemWatermark, h backend.KeyHash, issued, floor uint64) {
	t.Helper()
	ctx := context.Background()
	if err := wm.CheckAndCommitCounter(ctx, h, opcertChainIssuedScope, issued); err != nil {
		t.Fatalf("seed issued: %v", err)
	}
	if err := wm.CheckAndCommitCounter(ctx, h, opcertCounterScope, issued); err != nil {
		t.Fatalf("seed counter: %v", err)
	}
	if err := wm.CheckAndRaiseFloor(ctx, h, opcertChainFloorScope, floor); err != nil {
		t.Fatalf("seed floor: %v", err)
	}
}

// A profiled key that is its backend's alone is bounded by the records it
// wrote before profile scoping until it has records under its profile.
func TestProfiledOpCert_SoleHolderKeepsLegacyBounds(t *testing.T) {
	t.Parallel()
	k := newFakeKey(t)
	c, wm := newProfiledCoordinator(t, k, profiledFakeBackend{"dev-preview", profPreview, k})
	seedLegacyOpCert(t, wm, k.hash, 5, 4)
	kes := make([]byte, kesVkeySize)
	id := k.hash.String()
	ctx := WithProfile(context.Background(), profPreview)

	if _, code, err := c.SignOpCertFromChain(ctx, kes, 100, 1, id); code != CodeConflict {
		t.Fatalf("chain 100 above legacy issued 5: want conflict, got code=%s err=%v", code, err)
	}
	if _, code, err := c.SignOpCertFromChain(ctx, kes, 3, 1, id); code != CodeConflict {
		t.Fatalf("chain 3 below legacy floor 4: want conflict, got code=%s err=%v", code, err)
	}
	if _, code, err := c.SignOpCert(ctx, kes, 5, 1, id); code != CodeConflict {
		t.Fatalf("issue 5 at legacy issued 5: want conflict, got code=%s err=%v", code, err)
	}
	for _, scope := range []string{opcertChainFloorScope, opcertChainIssuedScope, opcertCounterScope} {
		if v, ok, _ := wm.CounterFor(context.Background(), k.hash, scope+"|"+profPreview); ok {
			t.Fatalf("refused request recorded %s|%s = %d", scope, profPreview, v)
		}
	}
	res, code, err := c.SignOpCertFromChain(ctx, kes, 5, 1, id)
	if err != nil || res.IssueCounter != 6 {
		t.Fatalf("chain 5 at legacy issued 5: res=%v code=%s err=%v", res, code, err)
	}
	if v, ok, _ := wm.CounterFor(context.Background(), k.hash, opcertChainIssuedScope+"|"+profPreview); !ok || v != 6 {
		t.Fatalf("profiled issued record = %d (ok=%v), want 6", v, ok)
	}
}

// With several holders the records written before profile scoping cannot be
// attributed to one profile, so they bound none of them.
func TestProfiledOpCert_SharedKeyIgnoresLegacyRecords(t *testing.T) {
	t.Parallel()
	k := newFakeKey(t)
	c, wm := newProfiledCoordinator(t, k,
		profiledFakeBackend{"dev-preview", profPreview, k},
		profiledFakeBackend{"dev-musashi", profMusashi, k})
	seedLegacyOpCert(t, wm, k.hash, 5, 4)
	kes := make([]byte, kesVkeySize)
	musashi := WithProfile(context.Background(), profMusashi)

	res, code, err := c.SignOpCertFromChain(musashi, kes, 0, 1, k.hash.String())
	if err != nil || res.IssueCounter != 1 {
		t.Fatalf("musashi chain 0 beside legacy floor 4: res=%v code=%s err=%v", res, code, err)
	}
}
