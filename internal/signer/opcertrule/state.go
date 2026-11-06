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

import "math"

// State is the counter record of a custody backend that serves both an
// explicit issue-counter path and opcert-next. Apply and Record are used by
// the root module only: the armory has no explicit path, and the shared
// vectors pin Next and CheckPeriod alone.
type State struct {
	// NextIssueNumber is the next number the explicit path accepts; every
	// number below it has been issued.
	NextIssueNumber uint64
	// Floor is the highest chain counter an opcert-next request reported.
	Floor uint64
	// LastIssued is the issue number of the latest certificate, 0 if none.
	LastIssued uint64
	// LastIssuedPeriod is the KES period of that certificate, 0 if unknown.
	LastIssuedPeriod uint64
}

// Apply returns the state after an opcert-next request and the issue number
// chosen, or the rule that refused it.
func Apply(cur State, chain, period uint64) (State, uint64, error) {
	// A record from before opcert-next has no last-issued number; the
	// explicit path issued every number below NextIssueNumber in sequence, so
	// the last one is the number before it.
	last := cur.LastIssued
	if last == 0 && cur.NextIssueNumber > 0 {
		last = cur.NextIssueNumber - 1
		// issue number 0 is below the rule's "unset" marker
		if last == 0 && chain > 0 {
			return State{}, 0, ErrAboveIssued
		}
	}
	// a floor of 0 refuses nothing, so it needs no separate set flag
	issue, floor, err := Next(cur.Floor, true, last, chain)
	if err != nil {
		return State{}, 0, err
	}
	// the explicit path refuses the same ceiling
	if issue >= math.MaxUint64-1 {
		return State{}, 0, ErrOutOfRange
	}
	// A chain counter that lags explicit issues would reissue an earlier
	// number, whose KES period is not recorded, and lower the last issued
	// number. Refuse it as a possible backdate.
	if issue < last {
		return State{}, 0, ErrKESBackdated
	}
	if err := CheckPeriod(
		issue,
		last,
		cur.LastIssuedPeriod,
		period,
	); err != nil {
		return State{}, 0, err
	}
	next := cur
	next.Floor = floor
	next.LastIssued, next.LastIssuedPeriod = issue, period
	next.NextIssueNumber = max(cur.NextIssueNumber, issue+1)
	return next, issue, nil
}

// Record returns the state after the explicit path issued issue, already
// checked to be NextIssueNumber, for a certificate at KES period period.
func Record(cur State, issue, period uint64) State {
	next := cur
	next.NextIssueNumber = issue + 1
	next.LastIssued, next.LastIssuedPeriod = issue, period
	return next
}
