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
	"fmt"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

func TestMemWatermark_ConflictAndIdempotent(t *testing.T) {
	wm := NewMemWatermark()
	ctx := context.Background()
	var key backend.KeyHash
	key[0] = 1

	if err := wm.Check(ctx, key, "tx:abc", []byte("payload-1")); err != nil {
		t.Fatalf("first check should pass: %v", err)
	}
	if err := wm.Commit(ctx, key, "tx:abc", []byte("payload-1")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// same payload, same scope -> idempotent OK
	if err := wm.Check(ctx, key, "tx:abc", []byte("payload-1")); err != nil {
		t.Fatalf("idempotent check should pass: %v", err)
	}
	// different payload, same scope -> conflict
	if err := wm.Check(ctx, key, "tx:abc", []byte("payload-2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	// different scope -> OK
	if err := wm.Check(ctx, key, "tx:def", []byte("payload-2")); err != nil {
		t.Fatalf("different scope should pass: %v", err)
	}
}

func TestMemWatermark_FirstWriterWins(t *testing.T) {
	wm := NewMemWatermark()
	ctx := context.Background()
	var key backend.KeyHash
	key[0] = 2

	payloadA := []byte("payload-A")
	payloadB := []byte("payload-B")

	if err := wm.Commit(ctx, key, "tx:fw", payloadA); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	// Second Commit with a different payload must be a no-op (first-writer-wins).
	if err := wm.Commit(ctx, key, "tx:fw", payloadB); err != nil {
		t.Fatalf("second commit should not error: %v", err)
	}
	// payloadA must still pass Check.
	if err := wm.Check(ctx, key, "tx:fw", payloadA); err != nil {
		t.Fatalf("payloadA should still pass after second Commit: %v", err)
	}
	// payloadB must conflict because the first write (payloadA) wins.
	if err := wm.Check(ctx, key, "tx:fw", payloadB); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for payloadB, got %v", err)
	}
}

func TestMemWatermark_CheckAndCommit(t *testing.T) {
	wm := NewMemWatermark()
	ctx := context.Background()
	var key backend.KeyHash
	key[0] = 3

	if err := wm.CheckAndCommit(ctx, key, "kes:1", []byte("payload-1")); err != nil {
		t.Fatalf("first CheckAndCommit: %v", err)
	}
	if err := wm.CheckAndCommit(ctx, key, "kes:1", []byte("payload-1")); err != nil {
		t.Fatalf("idempotent CheckAndCommit: %v", err)
	}
	if err := wm.CheckAndCommit(ctx, key, "kes:1", []byte("payload-2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestWarningMemWatermarkBoundsRecords(t *testing.T) {
	wm := NewWarningMemWatermark()
	ctx := context.Background()
	var key backend.KeyHash
	key[0] = 4

	for i := 0; i <= maxWarningRecords; i++ {
		if err := wm.Commit(ctx, key, fmt.Sprintf("tx:%08x", i), []byte("payload")); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	if got := len(wm.records); got != maxWarningRecords {
		t.Fatalf("retained records = %d, want %d", got, maxWarningRecords)
	}
	if err := wm.Check(ctx, key, "tx:00000000", []byte("different")); err != nil {
		t.Fatalf("oldest record was not evicted: %v", err)
	}
	if err := wm.Check(ctx, key, fmt.Sprintf("tx:%08x", maxWarningRecords), []byte("different")); !errors.Is(err, ErrConflict) {
		t.Fatalf("newest record: got %v, want ErrConflict", err)
	}
}

func TestMemWatermarkDoesNotEvictEnforcedRecords(t *testing.T) {
	wm := NewMemWatermark()
	ctx := context.Background()
	var key backend.KeyHash
	key[0] = 5

	for i := 0; i <= maxWarningRecords; i++ {
		if err := wm.CheckAndCommit(ctx, key, fmt.Sprintf("scope:%08x", i), []byte("payload")); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	if err := wm.Check(ctx, key, "scope:00000000", []byte("different")); !errors.Is(err, ErrConflict) {
		t.Fatalf("oldest enforced record: got %v, want ErrConflict", err)
	}
}

func TestWarningMemWatermarkConcurrentBound(t *testing.T) {
	const (
		limit     = 64
		workers   = 8
		perWorker = 128
	)
	wm := newMemWatermark(limit)
	ctx := context.Background()
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			var key backend.KeyHash
			key[0] = byte(worker)
			for i := 0; i < perWorker; i++ {
				if err := wm.Commit(ctx, key, fmt.Sprintf("tx:%d:%d", worker, i), []byte("payload")); err != nil {
					t.Errorf("worker %d commit %d: %v", worker, i, err)
				}
			}
		}(worker)
	}
	wg.Wait()

	wm.mu.Lock()
	defer wm.mu.Unlock()
	if got, want := len(wm.records), limit; got != want {
		t.Fatalf("retained records = %d, want %d", got, want)
	}
	if got := len(wm.recordOrder); got != limit {
		t.Fatalf("retention ring entries = %d, want %d", got, limit)
	}
}
