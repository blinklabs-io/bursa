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

package opcertrule

import (
	"errors"
	"math"
	"testing"
)

// apply runs one Apply step and fails unless it issues want.
func apply(t *testing.T, s State, chain, period, want uint64) State {
	t.Helper()
	next, issue, err := Apply(s, chain, period)
	if err != nil || issue != want {
		t.Fatalf("chain %d period %d: issue %d err %v, want issue %d",
			chain, period, issue, err, want)
	}
	if next.LastIssued < s.LastIssued {
		t.Fatalf("chain %d lowered last issued: %+v -> %+v", chain, s, next)
	}
	return next
}

// refuse fails unless Apply refuses with want.
func refuse(t *testing.T, s State, chain, period uint64, want error) {
	t.Helper()
	if _, _, err := Apply(s, chain, period); !errors.Is(err, want) {
		t.Fatalf("chain %d period %d: err %v, want %v",
			chain, period, err, want)
	}
}

func TestApplyRules(t *testing.T) {
	t.Parallel()

	s := apply(t, State{}, 0, 100, 1)
	want := State{
		NextIssueNumber: 2, LastIssued: 1, LastIssuedPeriod: 100,
	}
	if s != want {
		t.Fatalf("first issue state %+v, want %+v", s, want)
	}
	if repeat := apply(t, s, 0, 100, 1); repeat != s {
		t.Fatalf("repeat changed the state: %+v", repeat)
	}
	s = apply(t, s, 0, 101, 1)
	refuse(t, s, 0, 100, ErrKESBackdated)
	s = apply(t, s, 1, 102, 2)
	if s.Floor != 1 || s.NextIssueNumber != 3 {
		t.Fatalf("after chain 1: %+v", s)
	}
	refuse(t, s, 0, 200, ErrBelowFloor)
	refuse(t, s, 3, 200, ErrAboveIssued)
	apply(t, s, 1, 102, 2)
}

// Explicit issues 0 through 6, then a chain counter that lags them: the
// earlier number has no recorded period and is refused.
func TestApplyRefusesNumberBelowLastIssued(t *testing.T) {
	t.Parallel()

	s := State{NextIssueNumber: 7, LastIssued: 6, LastIssuedPeriod: 60}
	refuse(t, s, 3, 10, ErrKESBackdated)
	apply(t, s, 5, 60, 6)
	apply(t, s, 6, 60, 7)
}

// Explicit issues 0, 1 and 2 at period 30, then chain 0 (issue 1).
func TestApplyChainZeroAfterExplicitThree(t *testing.T) {
	t.Parallel()

	var s State
	for i := range uint64(3) {
		s = Record(s, i, 30)
	}
	want := State{NextIssueNumber: 3, LastIssued: 2, LastIssuedPeriod: 30}
	if s != want {
		t.Fatalf("explicit state %+v, want %+v", s, want)
	}
	refuse(t, s, 0, 20, ErrKESBackdated)
	refuse(t, s, 1, 20, ErrKESBackdated)
	apply(t, s, 1, 30, 2)
}

// A record from before opcert-next carries only NextIssueNumber: the last
// issued number is the one before it and its period is unknown.
func TestApplyLegacyRecord(t *testing.T) {
	t.Parallel()

	s := State{NextIssueNumber: 7}
	refuse(t, s, 7, 10, ErrAboveIssued)
	refuse(t, s, 4, 10, ErrKESBackdated)
	s = apply(t, s, 5, 0, 6)
	s = apply(t, s, 6, 10, 7)
	if s.NextIssueNumber != 8 || s.Floor != 6 {
		t.Fatalf("after legacy record: %+v", s)
	}

	// only issue 0 was issued: no chain counter above it is accepted
	refuse(t, State{NextIssueNumber: 1}, 1, 10, ErrAboveIssued)
	apply(t, State{NextIssueNumber: 1}, 0, 10, 1)
}

func TestApplyOutOfRange(t *testing.T) {
	t.Parallel()

	refuse(t, State{}, math.MaxUint64, 10, ErrOutOfRange)
	// the explicit path's ceiling: no issue at or above MaxUint64-1
	refuse(t, State{}, math.MaxUint64-2, 10, ErrOutOfRange)
	apply(t, State{}, math.MaxUint64-3, 10, math.MaxUint64-2)
}
