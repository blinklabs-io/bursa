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
