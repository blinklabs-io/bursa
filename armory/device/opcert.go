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

package device

import (
	"errors"
	"math"
)

var errBelowFloor = errors.New(
	"chain counter below the recorded on-chain counter",
)

var errAboveIssued = errors.New(
	"chain counter above the last counter the device issued",
)

// errKESBackdated refuses a reissue of the last issued counter at a KES period
// below the one the signing log holds for it. Both opcerts stay valid until
// one forges, so a backdated reissue would only extend an older KES key's
// window.
var errKESBackdated = errors.New(
	"KES period below the logged opcert at this counter",
)

// nextOpCert picks the opcert issue number from the on-chain counter chain:
// the last counter seen in a block the pool forged, 0 if none. A header's
// counter must be at least that and at most one more, so the next opcert is
// always chain+1, and reissuing it is allowed while the pool hasn't forged.
// The floor is the highest chain counter ever reported and refuses a host
// that reports one lower. The ledger only holds counters the device issued, so
// once lastIssued is set (non-zero; an issued counter is at least 1) a chain
// counter above it is refused: it would yield an opcert the ledger rejects and
// push the floor above every counter it accepts. Unset, as on a record from
// before the field, there is no bound until the first opcert-next sets it.
func nextOpCert(
	floor uint64,
	floorSet bool,
	lastIssued, chain uint64,
) (issue uint64, newFloor uint64, err error) {
	if floorSet && chain < floor {
		return 0, 0, errBelowFloor
	}

	if lastIssued != 0 && chain > lastIssued {
		return 0, 0, errAboveIssued
	}

	if chain == math.MaxUint64 {
		return 0, 0, errors.New("chain counter out of range")
	}

	return chain + 1, max(floor, chain), nil
}
