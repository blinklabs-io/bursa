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

	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// newResetFenceCoordinator returns a coordinator over a sqlite store (the
// reset needs a store that supports it) whose first issued-record lookup
// pauses. The store holds floor 4 and issued 5 for the key.
func newResetFenceCoordinator(
	t *testing.T,
	mode watermark.Mode,
) (*Coordinator, *pausingCounterWatermark, *watermark.SqliteWatermark, *fakeKey) {
	t.Helper()
	wm, _ := newSqliteForReset(t)
	k := newFakeKey(t)
	ctx := context.Background()
	if err := wm.CheckAndRaiseFloor(ctx, k.hash, opcertChainFloorScope, 4); err != nil {
		t.Fatalf("seed floor: %v", err)
	}
	if err := wm.CheckAndRaiseFloor(ctx, k.hash, opcertChainIssuedScope, 5); err != nil {
		t.Fatalf("seed issued: %v", err)
	}
	pw := &pausingCounterWatermark{
		Watermark: wm,
		counter:   wm,
		paused:    make(chan struct{}),
		release:   make(chan struct{}),
	}
	c, _ := newOpCertCoordinator(t, k, pw, mode)
	return c, pw, wm, k
}

func requireRecords(
	t *testing.T,
	wm watermark.CounterReader,
	k *fakeKey,
	floor *uint64,
	issued *uint64,
) {
	t.Helper()
	got, err := ReadOpCertRecords(context.Background(), wm, k.hash, "")
	if err != nil {
		t.Fatalf("read records: %v", err)
	}
	eq := func(a, b *uint64) bool {
		return a == nil && b == nil || a != nil && b != nil && *a == *b
	}
	show := func(p *uint64) any {
		if p == nil {
			return "none"
		}
		return *p
	}
	if !eq(got.ChainFloor, floor) || !eq(got.ChainIssued, issued) {
		t.Fatalf(
			"records floor=%v issued=%v, want floor=%v issued=%v",
			show(got.ChainFloor), show(got.ChainIssued),
			show(floor), show(issued),
		)
	}
}

// A request that passed its pre-sign checks is refused at commit when a
// reset ran meanwhile: no signature, and the reset's floor and cleared issued
// record stand.
func TestSignOpCertFromChain_ResetBetweenCheckAndCommit(t *testing.T) {
	t.Parallel()
	for name, issue := range map[string]bool{"chain": false, "issue": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, pw, wm, k := newResetFenceCoordinator(t, watermark.ModeEnforce)
			ctx := context.Background()
			kes := make([]byte, kesVkeySize)

			first := func() (*OpCertResult, ErrorCode, error) {
				return c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String())
			}
			if issue {
				first = func() (*OpCertResult, ErrorCode, error) {
					return c.SignOpCert(ctx, kes, 9, 100, k.hash.String())
				}
			}
			res, code, err := raceOpCert(t, pw, first,
				func() (*OpCertResult, ErrorCode, error) {
					_, _, rerr := ResetOpCertChain(
						ctx, wm, watermark.ModeEnforce, k.hash, "", 2, true,
					)
					return nil, "", rerr
				},
			)
			if code != CodeConflict || err == nil || res != nil {
				t.Fatalf(
					"request across a reset: res=%v code=%s err=%v, want no signature and %s",
					res,
					code,
					err,
					CodeConflict,
				)
			}
			requireRecords(t, wm, k, u64p(2), nil)
			if _, ok, _ := wm.CounterFor(ctx, k.hash, opcertCounterScope); ok {
				t.Fatal("explicit issue counter recorded by a refused request")
			}

			// a fresh request reads the new generation and signs
			res, code, err = c.SignOpCertFromChain(
				ctx,
				kes,
				2,
				101,
				k.hash.String(),
			)
			if err != nil {
				t.Fatalf("chain 2 after reset: %v (%s)", err, code)
			}
			verifyChainOpCert(t, res, kes, 3, 101)
		})
	}
}

// Warn mode signs a request that raced a reset but records nothing.
func TestSignOpCertFromChain_ResetBetweenCheckAndCommitWarn(t *testing.T) {
	t.Parallel()
	c, pw, wm, k := newResetFenceCoordinator(t, watermark.ModeWarn)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	res, code, err := raceOpCert(t, pw,
		func() (*OpCertResult, ErrorCode, error) {
			return c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String())
		},
		func() (*OpCertResult, ErrorCode, error) {
			_, _, rerr := ResetOpCertChain(
				ctx, wm, watermark.ModeWarn, k.hash, "", 2, true,
			)
			return nil, "", rerr
		},
	)
	if err != nil {
		t.Fatalf("warn mode request across a reset: %v (%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 5, 100)
	requireRecords(t, wm, k, u64p(2), nil)
}

// A commit that finishes before the reset is overwritten by it.
func TestSignOpCertFromChain_CommitThenReset(t *testing.T) {
	t.Parallel()
	wm, _ := newSqliteForReset(t)
	k := newFakeKey(t)
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	res, code, err := c.SignOpCertFromChain(ctx, kes, 4, 100, k.hash.String())
	if err != nil {
		t.Fatalf("chain 4: %v (%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 5, 100)
	requireRecords(t, wm, k, u64p(4), u64p(5))

	if _, _, err := ResetOpCertChain(
		ctx, wm, watermark.ModeEnforce, k.hash, "", 2, true,
	); err != nil {
		t.Fatalf("reset: %v", err)
	}
	requireRecords(t, wm, k, u64p(2), nil)
}

// With no reset, repeated signing is unaffected by the fence, and a reset
// between two sequential requests does not refuse the second.
func TestSignOpCertFromChain_FenceNoReset(t *testing.T) {
	t.Parallel()
	wm, _ := newSqliteForReset(t)
	k := newFakeKey(t)
	c, _ := newOpCertCoordinator(t, k, wm, watermark.ModeEnforce)
	ctx := context.Background()
	kes := make([]byte, kesVkeySize)

	for i, chain := range []uint64{4, 4, 5} {
		res, code, err := c.SignOpCertFromChain(
			ctx, kes, chain, 100+uint64(i), k.hash.String(),
		)
		if err != nil {
			t.Fatalf("chain %d: %v (%s)", chain, err, code)
		}
		verifyChainOpCert(t, res, kes, chain+1, 100+uint64(i))
	}
	if res, code, err := c.SignOpCert(ctx, kes, 7, 110, k.hash.String()); err != nil {
		t.Fatalf("issue 7: %v (%s)", err, code)
	} else {
		verifyChainOpCert(t, res, kes, 7, 110)
	}
	requireRecords(t, wm, k, u64p(5), u64p(7))

	if _, _, err := ResetOpCertChain(
		ctx, wm, watermark.ModeEnforce, k.hash, "", 8, true,
	); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if res, code, err := c.SignOpCertFromChain(ctx, kes, 8, 111, k.hash.String()); err != nil {
		t.Fatalf("chain 8 after reset: %v (%s)", err, code)
	} else {
		verifyChainOpCert(t, res, kes, 9, 111)
	}
}
