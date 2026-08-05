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
	"math"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

func TestSqliteWatermark(t *testing.T) {
	dir := t.TempDir()
	wm, err := NewSqliteWatermark(filepath.Join(dir, "wm.db"))
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	defer wm.Close()
	ctx := context.Background()
	var key backend.KeyHash
	key[1] = 9

	if err := wm.Check(ctx, key, "kes:42", []byte("blockA")); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if err := wm.Commit(ctx, key, "kes:42", []byte("blockA")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := wm.Check(ctx, key, "kes:42", []byte("blockB")); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	if err := wm.Check(ctx, key, "kes:42", []byte("blockA")); err != nil {
		t.Fatalf("idempotent check: %v", err)
	}
	if err := wm.CheckAndCommit(ctx, key, "kes:43", []byte("blockA")); err != nil {
		t.Fatalf("check and commit: %v", err)
	}
	if err := wm.CheckAndCommit(ctx, key, "kes:43", []byte("blockA")); err != nil {
		t.Fatalf("idempotent check and commit: %v", err)
	}
	if err := wm.CheckAndCommit(ctx, key, "kes:43", []byte("blockB")); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict from check and commit, got %v", err)
	}
}

func TestSqliteWatermark_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "wm.db")
	ctx := context.Background()
	var key backend.KeyHash
	key[2] = 7

	// First open: commit a payload.
	wm, err := NewSqliteWatermark(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteWatermark (first open): %v", err)
	}
	if err := wm.Commit(ctx, key, "tx:persist", []byte("block-1")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := wm.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Second open: the record must survive.
	wm2, err := NewSqliteWatermark(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteWatermark (second open): %v", err)
	}
	defer wm2.Close()

	// Same payload -> nil (idempotent).
	if err := wm2.Check(ctx, key, "tx:persist", []byte("block-1")); err != nil {
		t.Fatalf("same payload after reopen should pass: %v", err)
	}
	// Different payload -> ErrConflict.
	if err := wm2.Check(ctx, key, "tx:persist", []byte("block-2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for different payload after reopen, got %v", err)
	}
}

// TestSqliteWatermark_CounterMonotonicity mirrors
// TestPostgres_CounterMonotonicity so the sqlite counter guard gets the same
// regression coverage as the postgres store: empty lookup, equal/lower
// rejection, and ordering across the int64 boundary (proving no lossy
// uint64->int64 conversion).
func TestSqliteWatermark_CounterMonotonicity(t *testing.T) {
	dir := t.TempDir()
	wm, err := NewSqliteWatermark(filepath.Join(dir, "wm.db"))
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	defer wm.Close()
	ctx := context.Background()
	var key backend.KeyHash
	key[3] = 11
	scope := "opcert-counter"

	if _, ok, err := wm.CounterFor(ctx, key, scope); err != nil || ok {
		t.Fatalf("CounterFor on empty: got (ok=%v, err=%v)", ok, err)
	}
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 5); err != nil {
		t.Fatalf("first commit at 5: %v", err)
	}
	if v, ok, err := wm.CounterFor(ctx, key, scope); err != nil || !ok || v != 5 {
		t.Fatalf("after first commit: got (v=%d, ok=%v, err=%v), want 5", v, ok, err)
	}
	// Equal and lower are regressions and record nothing.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 5); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("re-commit at 5: want ErrCounterRegression, got %v", err)
	}
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 4); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("commit at 4: want ErrCounterRegression, got %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != 5 {
		t.Fatalf("stored counter regressed to %d after rejected commits, want 5", v)
	}
	// Strictly greater advances, including a large jump past int64-relevant values.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 6); err != nil {
		t.Fatalf("commit at 6: %v", err)
	}
	const big = uint64(1) << 63 // exceeds math.MaxInt64; proves no lossy int64 cast
	if err := wm.CheckAndCommitCounter(ctx, key, scope, big); err != nil {
		t.Fatalf("commit at 2^63: %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != big {
		t.Fatalf("after 2^63 jump: got %d, want %d", v, big)
	}
	// A value below 2^63 must now regress (ordering correct across the int64 boundary).
	if err := wm.CheckAndCommitCounter(ctx, key, scope, big-1); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("commit below high watermark: want ErrCounterRegression, got %v", err)
	}
	// The all-ones counter (math.MaxUint64) must also advance correctly.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, math.MaxUint64); err != nil {
		t.Fatalf("commit at MaxUint64: %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != math.MaxUint64 {
		t.Fatalf("after MaxUint64 commit: got %d, want %d", v, uint64(math.MaxUint64))
	}
}

// TestSqliteWatermark_CounterPerKeyIsolation proves counters are tracked
// independently per (key, scope) — advancing one key's counter must not
// affect another key's.
func TestSqliteWatermark_CounterPerKeyIsolation(t *testing.T) {
	dir := t.TempDir()
	wm, err := NewSqliteWatermark(filepath.Join(dir, "wm.db"))
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	defer wm.Close()
	ctx := context.Background()
	var keyA, keyB backend.KeyHash
	keyA[4] = 1
	keyB[4] = 2
	scope := "opcert-counter"

	if err := wm.CheckAndCommitCounter(ctx, keyA, scope, 10); err != nil {
		t.Fatalf("keyA commit: %v", err)
	}
	if err := wm.CheckAndCommitCounter(ctx, keyB, scope, 1); err != nil {
		t.Fatalf("keyB commit at 1 must be independent of keyA: %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, keyA, scope); v != 10 {
		t.Fatalf("keyA counter changed to %d, want 10", v)
	}
	if v, _, _ := wm.CounterFor(ctx, keyB, scope); v != 1 {
		t.Fatalf("keyB counter %d, want 1", v)
	}
}

// TestSqliteWatermark_CounterPersistsAcrossReopen proves the counter
// watermark, like the payload watermark, survives a close/reopen cycle.
func TestSqliteWatermark_CounterPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "wm.db")
	ctx := context.Background()
	var key backend.KeyHash
	key[5] = 3
	scope := "opcert-counter"

	wm, err := NewSqliteWatermark(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteWatermark (first open): %v", err)
	}
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 7); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := wm.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	wm2, err := NewSqliteWatermark(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteWatermark (second open): %v", err)
	}
	defer wm2.Close()

	if v, ok, err := wm2.CounterFor(ctx, key, scope); err != nil || !ok || v != 7 {
		t.Fatalf("counter must survive reopen: got (v=%d, ok=%v, err=%v), want 7", v, ok, err)
	}
	// A regression must still be rejected against the reloaded high watermark.
	if err := wm2.CheckAndCommitCounter(ctx, key, scope, 7); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("re-commit at 7 after reopen: want ErrCounterRegression, got %v", err)
	}
	if err := wm2.CheckAndCommitCounter(ctx, key, scope, 8); err != nil {
		t.Fatalf("commit at 8 after reopen: %v", err)
	}
}
