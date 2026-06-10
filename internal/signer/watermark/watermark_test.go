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
