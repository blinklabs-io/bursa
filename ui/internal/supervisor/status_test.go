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
package supervisor

import (
	"testing"
	"time"
)

func TestCaughtUp(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		latest    time.Time
		threshold time.Duration
		want      bool
	}{
		{"zero time is never caught up", time.Time{}, 2 * time.Minute, false},
		{"recent block is caught up", now.Add(-30 * time.Second), 2 * time.Minute, true},
		{"old block is not caught up", now.Add(-10 * time.Minute), 2 * time.Minute, false},
		{"exactly at threshold is caught up", now.Add(-2 * time.Minute), 2 * time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := caughtUp(tc.latest, now, tc.threshold); got != tc.want {
				t.Fatalf("caughtUp() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDeriveState(t *testing.T) {
	cases := []struct {
		name       string
		haveBlk    bool
		isCaughtUp bool
		want       NodeState
	}{
		{"no block yet", false, false, StateSyncing},
		{"behind tip", true, false, StateSyncing},
		{"caught up", true, true, StateReady},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveState(tc.haveBlk, tc.isCaughtUp); got != tc.want {
				t.Fatalf("deriveState() = %q, want %q", got, tc.want)
			}
		})
	}
}
