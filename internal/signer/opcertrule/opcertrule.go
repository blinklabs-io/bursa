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

// Package opcertrule holds the rules for choosing an operational-certificate
// issue number from the on-chain counter ("opcert-next"). Next mirrors
// armory/device.nextOpCert, which the root module cannot import; the vectors
// in armory/device/testdata/opcert_vectors.json pin both copies to the same
// decisions and refusal strings.
package opcertrule

import (
	"errors"
	"math"
)

var (
	// ErrBelowFloor reports a chain counter below the highest one recorded.
	ErrBelowFloor = errors.New(
		"chain counter below the recorded on-chain counter",
	)
	// ErrAboveIssued reports a chain counter above the last issued counter.
	ErrAboveIssued = errors.New(
		"chain counter above the last counter the device issued",
	)
	// ErrOutOfRange reports a chain counter that has no successor.
	ErrOutOfRange = errors.New("chain counter out of range")
	// ErrKESBackdated reports a reissue at a KES period below the one
	// recorded for the same issue number.
	ErrKESBackdated = errors.New(
		"KES period below the logged opcert at this counter",
	)
)

// Next picks the opcert issue number from the chain counter: chain+1, so
// reissuing the same number is allowed while the pool has not forged. floor
// is the highest chain counter ever reported; a lower report is refused.
// lastIssued is the last issue number handed out, 0 if none (an issued number
// is at least 1); once set, a chain counter above it is refused. It returns
// the issue number and the raised floor.
func Next(
	floor uint64,
	floorSet bool,
	lastIssued, chain uint64,
) (issue uint64, newFloor uint64, err error) {
	if floorSet && chain < floor {
		return 0, 0, ErrBelowFloor
	}

	if lastIssued != 0 && chain > lastIssued {
		return 0, 0, ErrAboveIssued
	}

	if chain == math.MaxUint64 {
		return 0, 0, ErrOutOfRange
	}

	return chain + 1, max(floor, chain), nil
}

// CheckPeriod refuses a reissue of lastIssued at a KES period below
// lastPeriod, the period recorded for it. A period of 0 is unknown and never
// refuses. A different issue number has no record here and is not checked.
func CheckPeriod(issue, lastIssued, lastPeriod, period uint64) error {
	if issue == lastIssued && period < lastPeriod {
		return ErrKESBackdated
	}

	return nil
}
