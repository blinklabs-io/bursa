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
)

var (
	_ FloorCommitWatermark = (*MemWatermark)(nil)
	_ FloorCommitWatermark = (*PostgresWatermark)(nil)
)

// floorCommitStore is a store with the combined floor and payload write and
// the reads that observe its effects.
type floorCommitStore interface {
	Watermark
	CounterWatermark
	FloorCommitWatermark
}

// checkFloorAndCommit runs the CheckAndRaiseFloorAndCommit rules against s.
func checkFloorAndCommit(t *testing.T, s floorCommitStore) {
	t.Helper()
	ctx := context.Background()
	key := randKey(t)
	const floor = "period-floor"

	floorIs := func(want uint64) {
		t.Helper()
		got, set, err := s.CounterFor(ctx, key, floor)
		if err != nil || !set || got != want {
			t.Fatalf("floor = %d %v %v, want %d true nil", got, set, err, want)
		}
	}

	// A fresh key: the floor and the payload are both written.
	if err := s.CheckAndRaiseFloorAndCommit(
		ctx, key, floor, 5, "slot:10", []byte("A"),
	); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	floorIs(5)
	if err := s.Check(ctx, key, "slot:10", []byte("B")); !errors.Is(
		err,
		ErrConflict,
	) {
		t.Fatalf("slot 10 not recorded: Check B got %v", err)
	}

	// An identical retry passes and changes nothing.
	if err := s.CheckAndRaiseFloorAndCommit(
		ctx, key, floor, 5, "slot:10", []byte("A"),
	); err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	floorIs(5)

	// A different payload for a recorded scope is refused, and the floor is
	// still raised, as CheckAndRaiseFloor then CheckAndCommit would leave it.
	if err := s.CheckAndRaiseFloorAndCommit(
		ctx, key, floor, 6, "slot:10", []byte("B"),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("different payload: want ErrConflict, got %v", err)
	}
	floorIs(6)

	// A value below the floor is refused and the payload is not recorded.
	if err := s.CheckAndRaiseFloorAndCommit(
		ctx, key, floor, 4, "slot:11", []byte("C"),
	); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("below floor: want ErrCounterRegression, got %v", err)
	}
	floorIs(6)
	if err := s.CheckAndCommit(ctx, key, "slot:11", []byte("D")); err != nil {
		t.Fatalf("slot 11 was recorded by a refused write: %v", err)
	}

	// A refused floor also leaves a conflicting payload unreported: the floor
	// refusal wins.
	if err := s.CheckAndRaiseFloorAndCommit(
		ctx, key, floor, 4, "slot:10", []byte("B"),
	); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("below floor on a recorded slot: want ErrCounterRegression, got %v", err)
	}

	// Counter values compare as numbers, not as decimal strings.
	const big = uint64(1) << 63
	if err := s.CheckAndRaiseFloorAndCommit(
		ctx, key, floor, big, "slot:12", []byte("E"),
	); err != nil {
		t.Fatalf("raise to 2^63: %v", err)
	}
	if err := s.CheckAndRaiseFloorAndCommit(
		ctx, key, floor, big-1, "slot:13", []byte("F"),
	); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("below 2^63 floor: want ErrCounterRegression, got %v", err)
	}
	floorIs(big)
}

func TestMemWatermark_CheckAndRaiseFloorAndCommit(t *testing.T) {
	t.Parallel()
	checkFloorAndCommit(t, NewMemWatermark())
}

func TestPostgres_CheckAndRaiseFloorAndCommit(t *testing.T) {
	checkFloorAndCommit(t, newTestPG(t, testPGDSN(t)))
}
