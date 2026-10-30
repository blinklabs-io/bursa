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

package confidentialspace

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type memoryCounterObject struct {
	mu         sync.Mutex
	data       []byte
	generation int64
}

func (o *memoryCounterObject) Load(
	context.Context,
) ([]byte, int64, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.data == nil {
		return nil, 0, false, nil
	}
	return append([]byte(nil), o.data...), o.generation, true, nil
}

func (o *memoryCounterObject) Store(
	_ context.Context,
	data []byte,
	generation int64,
	exists bool,
) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if exists {
		if o.data == nil || generation != o.generation {
			return status.Error(codes.FailedPrecondition, "generation changed")
		}
	} else if o.data != nil {
		return status.Error(codes.FailedPrecondition, "object exists")
	}
	o.data = append([]byte(nil), data...)
	o.generation++
	return nil
}

func TestCounterSequence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		expected uint64
		next     uint64
		wantErr  bool
	}{
		{name: "bootstrap", next: 0},
		{name: "oversized bootstrap", next: 1, wantErr: true},
		{name: "maximum bootstrap", next: math.MaxUint64, wantErr: true},
		{name: "sequential", expected: 8, next: 8},
		{name: "repeat", expected: 8, next: 7, wantErr: true},
		{name: "regression", expected: 8, next: 6, wantErr: true},
		{name: "skipped", expected: 8, next: 9, wantErr: true},
		{
			name:     "near maximum sequential",
			expected: math.MaxUint64 - 1,
			next:     math.MaxUint64 - 1,
			wantErr:  true,
		},
		{
			name:     "maximum request",
			expected: math.MaxUint64,
			next:     math.MaxUint64,
			wantErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkCounterSequence(test.expected, test.next)
			if test.wantErr && !errors.Is(err, ErrCounterRegression) {
				t.Fatalf("checkCounterSequence() error = %v, want ErrCounterRegression", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("checkCounterSequence() error = %v", err)
			}
		})
	}
}

func TestMemoryCounterStoreConcurrentAdvance(t *testing.T) {
	t.Parallel()
	store := &memoryStore{}
	if err := store.Prepare(t.Context(), backend.KeyHash{}, true); err != nil {
		t.Fatal(err)
	}
	const goroutines = 16
	start := make(chan struct{})
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := store.CheckAndAdvance(
				t.Context(),
				backend.KeyHash{},
				0,
			)
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
				return
			}
			if !errors.Is(err, ErrCounterRegression) {
				t.Errorf("CheckAndAdvance() error = %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful concurrent advances = %d, want 1", successes)
	}
	if err := store.CheckAndAdvance(
		t.Context(),
		backend.KeyHash{},
		1,
	); err != nil {
		t.Fatalf("sequential advance after race: %v", err)
	}
}

func TestCounterStateRequiresNextIssueNumber(t *testing.T) {
	t.Parallel()
	key := backend.KeyHash{}.String()
	for _, test := range []struct {
		name  string
		state counterStateWire
	}{
		{
			name: "v2 missing next issue number",
			state: counterStateWire{
				Version: counterStateVersion,
				KeyHash: key,
			},
		},
		{
			name: "v1 missing issue number",
			state: counterStateWire{
				Version: counterStateVersionV1,
				KeyHash: key,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := normalizeCounterState(test.state, key); err == nil {
				t.Fatal("incomplete counter state accepted")
			}
		})
	}
}

func TestCounterStateV1Migration(t *testing.T) {
	t.Parallel()
	key := backend.KeyHash{}
	issueNumber := uint64(7)
	data, err := json.Marshal(counterStateWire{
		Version:     counterStateVersionV1,
		KeyHash:     key.String(),
		IssueNumber: &issueNumber,
	})
	if err != nil {
		t.Fatal(err)
	}
	object := &memoryCounterObject{data: data, generation: 1}
	store := &CloudCounterStore{object: object}

	const goroutines = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := store.Prepare(t.Context(), key, false); err != nil {
				t.Errorf("Prepare() error = %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	state, _, exists, err := store.loadCurrent(t.Context(), key.String())
	if err != nil {
		t.Fatal(err)
	}
	if !exists || state.Version != counterStateVersion ||
		state.NextIssueNumber != issueNumber+1 {
		t.Fatalf("migrated state = %+v, exists = %v", state, exists)
	}
	object.mu.Lock()
	generation := object.generation
	object.mu.Unlock()
	if generation != 2 {
		t.Fatalf("generation = %d, want exactly one migration write", generation)
	}
	if err := store.CheckAndAdvance(t.Context(), key, issueNumber+1); err != nil {
		t.Fatalf("advance after migration: %v", err)
	}
}

func TestCounterStateV1MigrationRejectsUnsafeState(t *testing.T) {
	t.Parallel()
	key := backend.KeyHash{}.String()
	maximum := uint64(math.MaxUint64)
	zero := uint64(0)
	for _, test := range []struct {
		name  string
		state counterStateWire
	}{
		{
			name: "maximum",
			state: counterStateWire{
				Version:     counterStateVersionV1,
				KeyHash:     key,
				IssueNumber: &maximum,
			},
		},
		{
			name: "mixed fields",
			state: counterStateWire{
				Version:         counterStateVersionV1,
				KeyHash:         key,
				IssueNumber:     &zero,
				NextIssueNumber: &zero,
			},
		},
		{
			name: "key mismatch",
			state: counterStateWire{
				Version:     counterStateVersionV1,
				KeyHash:     backend.KeyHash{1}.String(),
				IssueNumber: &zero,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := normalizeCounterState(test.state, key); err == nil {
				t.Fatal("unsafe legacy state accepted")
			}
		})
	}
}
