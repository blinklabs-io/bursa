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
	"os"
	"reflect"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// resetTestStore is a store the admin reset runs against.
type resetTestStore interface {
	watermark.CounterWatermark
	watermark.CounterAdmin
}

func seedCounters(
	t *testing.T,
	wm watermark.CounterWatermark,
	key backend.KeyHash,
	records map[string]uint64,
) {
	t.Helper()
	for scope, v := range records {
		if err := wm.CheckAndRaiseFloor(context.Background(), key, scope, v); err != nil {
			t.Fatalf("seed %s: %v", scope, err)
		}
	}
}

// requireCounters checks each scope's record; a nil value requires none.
func requireCounters(
	t *testing.T,
	wm watermark.CounterReader,
	key backend.KeyHash,
	want map[string]*uint64,
) {
	t.Helper()
	for scope, w := range want {
		v, ok, err := wm.CounterFor(context.Background(), key, scope)
		if err != nil {
			t.Fatalf("read %s: %v", scope, err)
		}
		switch {
		case w == nil && ok:
			t.Fatalf("%s = %d, want none", scope, v)
		case w != nil && (!ok || v != *w):
			t.Fatalf("%s = %d (ok=%v), want %d", scope, v, ok, *w)
		}
	}
}

// A profiled sole holder whose key still has the records written before
// profile scoping, with the issued record above the chain, is refused a
// failback. The profiled reset clears the legacy issued record with its own,
// so the next chain-counter request issues chain + 1. The legacy floor, above
// the reset value, is left alone: the reset's floor under the profile is
// read in its place.
func TestResetOpCertChain_ProfiledFailbackClearsLegacyIssued(t *testing.T) {
	t.Parallel()
	wm, _ := newSqliteForReset(t)
	k := newFakeKey(t)
	c := newProfiledStoreCoordinator(t, k, wm, watermark.ModeEnforce)
	seedCounters(t, wm, k.hash, map[string]uint64{
		opcertChainFloorScope:  11,
		opcertChainIssuedScope: 12,
		opcertCounterScope:     12,
	})
	ctx := WithProfile(context.Background(), profPreview)
	kes := make([]byte, kesVkeySize)
	id := k.hash.String()

	if _, code, err := c.SignOpCertFromChain(ctx, kes, 10, 100, id); code != CodeConflict {
		t.Fatalf("chain 10 under legacy records: want conflict, got code=%s err=%v", code, err)
	}

	before, after, err := ResetOpCertChain(
		context.Background(), wm, watermark.ModeEnforce, k.hash, profPreview, 10, true,
	)
	if err != nil {
		t.Fatalf("profiled reset: %v", err)
	}
	res, code, err := c.SignOpCertFromChain(ctx, kes, 10, 101, id)
	if err != nil {
		t.Fatalf("chain 10 after the profiled reset: %v (%s)", err, code)
	}
	verifyChainOpCert(t, res, kes, 11, 101)
	if before.LegacyChainIssued == nil || *before.LegacyChainIssued != 12 ||
		before.ChainIssued != nil || before.ChainFloor != nil {
		t.Fatalf("before = %+v, want only the legacy issued 12", before)
	}
	if after.LegacyChainIssued != nil || after.ChainIssued != nil ||
		after.ChainFloor == nil || *after.ChainFloor != 10 {
		t.Fatalf("after = %+v, want floor 10 and no issued record", after)
	}
	requireCounters(t, wm, k.hash, map[string]*uint64{
		opcertChainFloorScope + "|" + profPreview:  u64p(10),
		opcertChainIssuedScope + "|" + profPreview: u64p(11),
		opcertResetGenScope + "|" + profPreview:    u64p(1),
		opcertChainIssuedScope:                     nil,
		opcertChainFloorScope:                      u64p(11),
		opcertCounterScope:                         u64p(12),
		opcertResetGenScope:                        nil,
	})

	if _, code, err := c.SignOpCertFromChain(ctx, kes, 9, 102, id); code != CodeConflict {
		t.Fatalf("chain 9 after reset to 10: want conflict, got code=%s err=%v", code, err)
	}
}

// checkProfiledAdminReset drives a profiled and an unprofiled reset against
// store: each changes only its own scopes, the profiled one also deletes the
// issued record written without a profile, and a dry run writes nothing.
func checkProfiledAdminReset(t *testing.T, store resetTestStore) {
	t.Helper()
	ctx := context.Background()
	key, other := newFakeKey(t).hash, newFakeKey(t).hash
	const p2 = profMusashi
	scoped := func(scope, profile string) string { return scope + "|" + profile }
	seedCounters(t, store, key, map[string]uint64{
		opcertChainFloorScope:                       11,
		opcertChainIssuedScope:                      12,
		opcertCounterScope:                          12,
		scoped(opcertChainFloorScope, profPreview):  7,
		scoped(opcertChainIssuedScope, profPreview): 8,
		scoped(opcertChainFloorScope, p2):           20,
		scoped(opcertChainIssuedScope, p2):          21,
	})
	seedCounters(t, store, other, map[string]uint64{opcertChainIssuedScope: 12})

	before, after, err := ResetOpCertChain(
		ctx, store, watermark.ModeEnforce, key, profPreview, 10, false,
	)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	wantBefore := OpCertRecords{
		ChainFloor: u64p(7), ChainIssued: u64p(8), LegacyChainIssued: u64p(12),
	}
	if !reflect.DeepEqual(before, wantBefore) {
		t.Fatalf("dry run before = %+v, want %+v", before, wantBefore)
	}
	if !reflect.DeepEqual(after, OpCertRecords{ChainFloor: u64p(10)}) {
		t.Fatalf("dry run planned after = %+v, want floor 10 only", after)
	}
	if now, err := ReadOpCertRecords(ctx, store, key, profPreview); err != nil ||
		!reflect.DeepEqual(now, before) {
		t.Fatalf("dry run changed the store: now %+v (%v), before %+v", now, err, before)
	}

	if _, _, err := ResetOpCertChain(
		ctx, store, watermark.ModeEnforce, key, profPreview, 10, true,
	); err != nil {
		t.Fatalf("profiled reset: %v", err)
	}
	requireCounters(t, store, key, map[string]*uint64{
		scoped(opcertChainFloorScope, profPreview):  u64p(10),
		scoped(opcertChainIssuedScope, profPreview): nil,
		scoped(opcertResetGenScope, profPreview):    u64p(1),
		opcertChainIssuedScope:                      nil,
		opcertChainFloorScope:                       u64p(11),
		opcertCounterScope:                          u64p(12),
		opcertResetGenScope:                         nil,
		scoped(opcertChainFloorScope, p2):           u64p(20),
		scoped(opcertChainIssuedScope, p2):          u64p(21),
		scoped(opcertResetGenScope, p2):             nil,
	})
	requireCounters(t, store, other, map[string]*uint64{
		opcertChainIssuedScope: u64p(12),
	})

	// an unprofiled reset leaves every profile's records alone
	if _, _, err := ResetOpCertChain(
		ctx, store, watermark.ModeEnforce, key, "", 3, true,
	); err != nil {
		t.Fatalf("unprofiled reset: %v", err)
	}
	requireCounters(t, store, key, map[string]*uint64{
		opcertChainFloorScope:                       u64p(3),
		opcertResetGenScope:                         u64p(1),
		scoped(opcertChainFloorScope, profPreview):  u64p(10),
		scoped(opcertResetGenScope, profPreview):    u64p(1),
		scoped(opcertChainFloorScope, p2):           u64p(20),
		scoped(opcertChainIssuedScope, p2):          u64p(21),
		scoped(opcertChainIssuedScope, profPreview): nil,
	})
}

func TestResetOpCertChain_ProfiledSqlite(t *testing.T) {
	t.Parallel()
	wm, _ := newSqliteForReset(t)
	checkProfiledAdminReset(t, wm)
}

func TestResetOpCertChain_ProfiledPostgres(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("BURSA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("BURSA_TEST_POSTGRES_DSN not set; skipping Postgres runtime tests")
	}
	wm, err := watermark.NewPostgresWatermark(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgresWatermark: %v", err)
	}
	t.Cleanup(wm.Close)
	checkProfiledAdminReset(t, wm)
}
