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

// counterStore is the subset of CounterWatermark exercised by the shared tests.
type counterStore interface {
	CounterWatermark
}

func runCounterMonotonicity(t *testing.T, wm counterStore) {
	t.Helper()
	ctx := context.Background()
	var key backend.KeyHash
	key[0] = 0xAA
	scope := "opcert-counter"

	// No record yet.
	if _, ok, err := wm.CounterFor(ctx, key, scope); err != nil || ok {
		t.Fatalf("CounterFor on empty: got (ok=%v, err=%v)", ok, err)
	}

	// First counter N stores N.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 5); err != nil {
		t.Fatalf("first commit at 5: %v", err)
	}
	if v, ok, err := wm.CounterFor(ctx, key, scope); err != nil || !ok || v != 5 {
		t.Fatalf("after first commit: got (v=%d, ok=%v, err=%v), want 5", v, ok, err)
	}

	// Same counter N -> regression.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 5); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("re-commit at 5: expected ErrCounterRegression, got %v", err)
	}
	// N-1 -> regression.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 4); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("commit at 4: expected ErrCounterRegression, got %v", err)
	}
	// Stored value unchanged after rejected commits.
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != 5 {
		t.Fatalf("stored counter regressed to %d after rejected commits, want 5", v)
	}
	// N+1 -> advances.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 6); err != nil {
		t.Fatalf("commit at 6: %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != 6 {
		t.Fatalf("after advance: got %d, want 6", v)
	}
	// A large jump advances too.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 1000); err != nil {
		t.Fatalf("commit at 1000: %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != 1000 {
		t.Fatalf("after jump: got %d, want 1000", v)
	}
}

func runCounterPerKeyIsolation(t *testing.T, wm counterStore) {
	t.Helper()
	ctx := context.Background()
	var keyA, keyB backend.KeyHash
	keyA[0] = 1
	keyB[0] = 2
	scope := "opcert-counter"

	if err := wm.CheckAndCommitCounter(ctx, keyA, scope, 10); err != nil {
		t.Fatalf("keyA commit: %v", err)
	}
	// keyB is independent: a low counter must still be accepted.
	if err := wm.CheckAndCommitCounter(ctx, keyB, scope, 1); err != nil {
		t.Fatalf("keyB commit at 1 should be independent of keyA: %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, keyA, scope); v != 10 {
		t.Fatalf("keyA stored counter changed to %d, want 10", v)
	}
	if v, _, _ := wm.CounterFor(ctx, keyB, scope); v != 1 {
		t.Fatalf("keyB stored counter %d, want 1", v)
	}
}

func TestMemWatermark_CounterMonotonicity(t *testing.T) {
	runCounterMonotonicity(t, NewMemWatermark())
}

func TestMemWatermark_CounterPerKeyIsolation(t *testing.T) {
	runCounterPerKeyIsolation(t, NewMemWatermark())
}

func TestSqliteWatermark_CounterMonotonicity(t *testing.T) {
	wm, err := NewSqliteWatermark(filepath.Join(t.TempDir(), "wm.db"))
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	defer wm.Close()
	runCounterMonotonicity(t, wm)
}

func TestSqliteWatermark_CounterPerKeyIsolation(t *testing.T) {
	wm, err := NewSqliteWatermark(filepath.Join(t.TempDir(), "wm.db"))
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	defer wm.Close()
	runCounterPerKeyIsolation(t, wm)
}

// TestSqliteWatermark_CounterPersistsAcrossReopen verifies durability: a counter
// committed before close is still enforced after the store is reopened.
func TestSqliteWatermark_CounterPersistsAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wm.db")
	ctx := context.Background()
	var key backend.KeyHash
	key[3] = 9
	scope := "opcert-counter"

	wm, err := NewSqliteWatermark(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteWatermark (first open): %v", err)
	}
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 42); err != nil {
		t.Fatalf("commit 42: %v", err)
	}
	if err := wm.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	wm2, err := NewSqliteWatermark(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteWatermark (second open): %v", err)
	}
	defer wm2.Close()

	if v, ok, err := wm2.CounterFor(ctx, key, scope); err != nil || !ok || v != 42 {
		t.Fatalf("after reopen: got (v=%d, ok=%v, err=%v), want 42", v, ok, err)
	}
	// A repeat of the persisted counter must still be rejected.
	if err := wm2.CheckAndCommitCounter(ctx, key, scope, 42); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("re-commit 42 after reopen: expected ErrCounterRegression, got %v", err)
	}
	// A higher counter still advances after reopen.
	if err := wm2.CheckAndCommitCounter(ctx, key, scope, 43); err != nil {
		t.Fatalf("commit 43 after reopen: %v", err)
	}
}

// runCounterConcurrency asserts that when many goroutines race to commit the
// same counter for the same key, exactly one succeeds.
func runCounterConcurrency(t *testing.T, wm counterStore) {
	t.Helper()
	ctx := context.Background()
	var key backend.KeyHash
	key[0] = 0x5A
	scope := "opcert-counter"

	const goroutines = 16
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := wm.CheckAndCommitCounter(ctx, key, scope, 7)
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
				return
			}
			if !errors.Is(err, ErrCounterRegression) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly 1 successful commit, got %d", successes)
	}
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != 7 {
		t.Fatalf("stored counter %d, want 7", v)
	}
}

func TestMemWatermark_CounterConcurrency(t *testing.T) {
	runCounterConcurrency(t, NewMemWatermark())
}

func TestSqliteWatermark_CounterConcurrency(t *testing.T) {
	wm, err := NewSqliteWatermark(filepath.Join(t.TempDir(), "wm.db"))
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	defer wm.Close()
	runCounterConcurrency(t, wm)
}
