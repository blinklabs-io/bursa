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

package watermark

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

func requireCounter(
	t *testing.T,
	wm CounterWatermark,
	key backend.KeyHash,
	scope string,
	want uint64,
	wantOK bool,
) {
	t.Helper()
	v, ok, err := wm.CounterFor(context.Background(), key, scope)
	if err != nil || ok != wantOK || v != want {
		t.Fatalf(
			"%s = (%d, %v, %v), want (%d, %v)",
			scope, v, ok, err, want, wantOK,
		)
	}
}

func requireGenRefused(t *testing.T, err error, scope string) {
	t.Helper()
	var re *CounterRegressionError
	if !errors.As(err, &re) || re.Scope != scope {
		t.Fatalf("err = %v, want a regression of scope %q", err, scope)
	}
}

// CounterEqual: no record is generation 0, a mismatch refuses the whole
// commit, and a match commits the other ops and writes nothing of its own
// value.
func checkCounterEqual(t *testing.T, wm CounterWatermark) {
	t.Helper()
	ctx := context.Background()
	key := randKey(t)
	eq := func(v uint64) CounterOp {
		return CounterOp{Scope: "gen", Value: v, Kind: CounterEqual}
	}
	floor := CounterOp{Scope: "floor", Value: 4, Kind: CounterFloor}

	requireGenRefused(
		t, wm.CheckAndCommitCounters(ctx, key, eq(1), floor), "gen",
	)
	requireCounter(t, wm, key, "floor", 0, false)

	if err := wm.CheckAndCommitCounters(ctx, key, eq(0), floor); err != nil {
		t.Fatalf("equal 0 with no record: %v", err)
	}
	requireCounter(t, wm, key, "floor", 4, true)
	if err := wm.CheckAndCommitCounters(ctx, key, eq(0), floor); err != nil {
		t.Fatalf("equal 0 again: %v", err)
	}
	requireGenRefused(
		t, wm.CheckAndCommitCounters(ctx, key, eq(2), floor), "gen",
	)
}

func TestMemWatermark_CounterEqual(t *testing.T) {
	t.Parallel()
	checkCounterEqual(t, NewMemWatermark())
}

func TestSqliteWatermark_CounterEqual(t *testing.T) {
	t.Parallel()
	wm, err := NewSqliteWatermark(filepath.Join(t.TempDir(), "wm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wm.Close() })
	checkCounterEqual(t, wm)
}

func TestPostgres_CounterEqual(t *testing.T) {
	t.Parallel()
	checkCounterEqual(t, newTestPG(t, testPGDSN(t)))
}

// A bump moves the generation by one, in the reset's transaction.
func checkAdminBump(t *testing.T, wm adminStore) {
	t.Helper()
	ctx := context.Background()
	key := randKey(t)
	eq := func(v uint64) CounterOp {
		return CounterOp{Scope: "gen", Value: v, Kind: CounterEqual}
	}
	floor := CounterOp{Scope: "floor", Value: 4, Kind: CounterFloor}
	set := []CounterSet{{Scope: "floor", Value: 2}}

	if err := wm.AdminResetCounters(ctx, key, set, nil, "gen"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	requireCounter(t, wm, key, "gen", 1, true)
	requireCounter(t, wm, key, "floor", 2, true)
	requireGenRefused(
		t, wm.CheckAndCommitCounters(ctx, key, eq(0), floor), "gen",
	)
	requireCounter(t, wm, key, "floor", 2, true)
	if err := wm.CheckAndCommitCounters(ctx, key, eq(1), floor); err != nil {
		t.Fatalf("equal 1 after one bump: %v", err)
	}
	if err := wm.AdminResetCounters(ctx, key, set, nil, "gen"); err != nil {
		t.Fatalf("second reset: %v", err)
	}
	requireCounter(t, wm, key, "gen", 2, true)

	if err := wm.AdminResetCounters(
		ctx, key, set, nil, "floor",
	); err == nil {
		t.Fatal("bump of a scope that is also set was accepted")
	}
}

func TestAdminBump_Sqlite(t *testing.T) {
	t.Parallel()
	wm, err := NewSqliteWatermark(filepath.Join(t.TempDir(), "wm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wm.Close() })
	checkAdminBump(t, wm)
}

func TestAdminBump_Postgres(t *testing.T) {
	t.Parallel()
	checkAdminBump(t, newTestPG(t, testPGDSN(t)))
}

// A reset racing commits that hold the generation they read before it: every
// commit either lands before the reset and is overwritten, or is refused. The
// final records are the reset's, whatever the interleaving.
func checkResetRacesCommits(t *testing.T, wm adminStore) {
	t.Helper()
	ctx := context.Background()
	for range 20 {
		key := randKey(t)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, 9)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- wm.CheckAndCommitCounters(ctx, key,
					CounterOp{Scope: "gen", Value: 0, Kind: CounterEqual},
					CounterOp{Scope: "floor", Value: 4, Kind: CounterFloor},
					CounterOp{
						Scope: "issued", Value: 5,
						Kind: CounterFloorFrom, Min: 4,
					},
				)
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- wm.AdminResetCounters(ctx, key,
				[]CounterSet{{Scope: "floor", Value: 2}},
				[]string{"issued"}, "gen")
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			var re *CounterRegressionError
			if err != nil && !(errors.As(err, &re) && re.Scope == "gen") {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		requireCounter(t, wm, key, "gen", 1, true)
		requireCounter(t, wm, key, "floor", 2, true)
		requireCounter(t, wm, key, "issued", 0, false)
	}
}

func TestResetRacesCommits_Sqlite(t *testing.T) {
	t.Parallel()
	wm, err := NewSqliteWatermark(filepath.Join(t.TempDir(), "wm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wm.Close() })
	checkResetRacesCommits(t, wm)
}

func TestResetRacesCommits_Postgres(t *testing.T) {
	t.Parallel()
	checkResetRacesCommits(t, newTestPG(t, testPGDSN(t)))
}
