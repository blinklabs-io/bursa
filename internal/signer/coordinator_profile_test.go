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
	"errors"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/policy"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// profiledFakeKey is a fakeKey served under a profile.
type profiledFakeKey struct {
	*fakeKey
	profile string
}

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
	return profiledFakeKey{fakeKey: b.key, profile: b.profile}
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
			if _, ok, _ := wm.CounterFor(ctx, k.hash, scope); ok {
				t.Errorf("refused request recorded scope %q", scope)
			}
		}
	})
}
