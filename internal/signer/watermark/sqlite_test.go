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
	"database/sql"
	"errors"
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

func TestSqliteWatermark_PingWritableDoesNotPersistProbe(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wm.db")
	wm, err := NewSqliteWatermark(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	defer wm.Close()
	ctx := context.Background()

	if err := wm.Ping(ctx); err != nil {
		t.Fatalf("Ping writable database: %v", err)
	}

	var payloadRows, counterRows int
	if err := wm.db.QueryRowContext(ctx, `
		SELECT
			(SELECT count(*) FROM watermark WHERE record_key = ?),
			(SELECT count(*) FROM counter_watermark WHERE record_key = ?)
	`, readinessProbeRecordKey, readinessProbeRecordKey).Scan(
		&payloadRows,
		&counterRows,
	); err != nil {
		t.Fatalf("count readiness probe rows: %v", err)
	}
	if payloadRows != 0 || counterRows != 0 {
		t.Fatalf(
			"readiness probe persisted rows: payload=%d counter=%d",
			payloadRows,
			counterRows,
		)
	}
}

func TestSqliteWatermark_PingRejectsReachableReadOnlyDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wm.db")
	writable, err := NewSqliteWatermark(dbPath)
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	if err := writable.Close(); err != nil {
		t.Fatalf("close writable database: %v", err)
	}

	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("open read-only database: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("read-only database should remain reachable: %v", err)
	}

	store := &SqliteWatermark{db: db}
	if err := store.Ping(ctx); err == nil {
		t.Fatal("Ping succeeded for a reachable read-only database")
	}
}

func TestSqliteWatermark_PingHonorsCancellation(t *testing.T) {
	wm, err := NewSqliteWatermark(filepath.Join(t.TempDir(), "wm.db"))
	if err != nil {
		t.Fatalf("NewSqliteWatermark: %v", err)
	}
	defer wm.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = wm.Ping(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ping canceled context: want context.Canceled, got %v", err)
	}
}
