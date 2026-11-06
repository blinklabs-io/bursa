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
)

// newProfiledResetFenceCoordinator is newResetFenceCoordinator for a key
// served under profPreview: the store holds floor 4 and issued 5 under that
// profile, and the first issued-record lookup pauses.
func newProfiledResetFenceCoordinator(
	t *testing.T,
	mode watermark.Mode,
) (*Coordinator, *pausingCounterWatermark, *watermark.SqliteWatermark, *fakeKey) {
	t.Helper()
	wm, _ := newSqliteForReset(t)
	k := newFakeKey(t)
	k.typ = backend.KeyTypePool
	ctx := context.Background()
	if err := wm.CheckAndRaiseFloor(
		ctx, k.hash, opcertChainFloorScope+"|"+profPreview, 4,
	); err != nil {
		t.Fatalf("seed floor: %v", err)
	}
	if err := wm.CheckAndRaiseFloor(
		ctx, k.hash, opcertChainIssuedScope+"|"+profPreview, 5,
	); err != nil {
		t.Fatalf("seed issued: %v", err)
	}
	pw := &pausingCounterWatermark{
		Watermark: wm,
		counter:   wm,
		paused:    make(chan struct{}),
		release:   make(chan struct{}),
	}
	eng, err := policy.NewEngine([]policy.KeyPolicy{{
		Hash:            k.hash.String(),
		AllowedRequests: []string{"opcert"},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	c := New(Deps{
		Resolver: backend.NewResolver(
			profiledFakeBackend{"dev-preview", profPreview, k},
		),
		Policy:    eng,
		Watermark: pw,
		WMMode:    mode,
		Metrics:   NewMetrics(),
	})
	return c, pw, wm, k
}

// profiledReset is the admin reset of the chain records under profPreview:
// floor to chain, issued cleared, the profile's generation bumped.
func profiledReset(
	ctx context.Context,
	wm *watermark.SqliteWatermark,
	k *fakeKey,
	chain uint64,
) error {
	return wm.AdminResetCounters(
		ctx,
		k.hash,
		[]watermark.CounterSet{
			{Scope: opcertChainFloorScope + "|" + profPreview, Value: chain},
		},
		[]string{opcertChainIssuedScope + "|" + profPreview},
		opcertResetGenScope+"|"+profPreview,
	)
}

func requireProfiledRecords(
	t *testing.T,
	wm watermark.CounterReader,
	k *fakeKey,
	floor *uint64,
	issued *uint64,
) {
	t.Helper()
	ctx := context.Background()
	for _, r := range []struct {
		scope string
		want  *uint64
	}{
		{opcertChainFloorScope + "|" + profPreview, floor},
		{opcertChainIssuedScope + "|" + profPreview, issued},
	} {
		v, ok, err := wm.CounterFor(ctx, k.hash, r.scope)
		if err != nil {
			t.Fatalf("read %s: %v", r.scope, err)
		}
		switch {
		case r.want == nil && ok:
			t.Fatalf("%s = %d, want none", r.scope, v)
		case r.want != nil && (!ok || v != *r.want):
			t.Fatalf("%s = %d (ok=%v), want %d", r.scope, v, ok, *r.want)
		}
	}
}

// A profiled request that passed its pre-sign checks is refused at commit
// when a reset of its profile's records ran meanwhile.
func TestProfiledOpCert_ResetBetweenCheckAndCommit(t *testing.T) {
	t.Parallel()
	c, pw, wm, k := newProfiledResetFenceCoordinator(t, watermark.ModeEnforce)
	ctx := WithProfile(context.Background(), profPreview)
	kes := make([]byte, kesVkeySize)

	res, code, err := raceOpCert(t, pw,
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String())
		},
		func() (*OpCertResult, ErrorCode, error) {
			return nil, "", profiledReset(context.Background(), wm, k, 2)
		},
	)
	if code != CodeConflict || err == nil || res != nil {
		t.Fatalf(
			"profiled request across a reset: res=%v code=%s err=%v, want no signature and %s",
			res,
			code,
			err,
			CodeConflict,
		)
	}
	requireProfiledRecords(t, wm, k, u64p(2), nil)

	res, code, err = c.SignOpCertFromChain(ctx, kes, 2, 101, k.hash.String())
	if err != nil {
		t.Fatalf("chain 2 after reset: %v (%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 3, 101)
}

// Warn mode signs a profiled request that raced a reset but records nothing.
func TestProfiledOpCert_ResetBetweenCheckAndCommitWarn(t *testing.T) {
	t.Parallel()
	c, pw, wm, k := newProfiledResetFenceCoordinator(t, watermark.ModeWarn)
	ctx := WithProfile(context.Background(), profPreview)
	kes := make([]byte, kesVkeySize)

	res, code, err := raceOpCert(t, pw,
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String())
		},
		func() (*OpCertResult, ErrorCode, error) {
			return nil, "", profiledReset(context.Background(), wm, k, 2)
		},
	)
	if err != nil {
		t.Fatalf("warn mode profiled request across a reset: %v (%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 5, 100)
	requireProfiledRecords(t, wm, k, u64p(2), nil)
}
