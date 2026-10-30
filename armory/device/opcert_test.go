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

import "testing"

func TestNextOpCert(t *testing.T) {
	for _, c := range []struct {
		floor    uint64
		floorSet bool
		chain    uint64
		issue    uint64
		newFloor uint64
		fail     bool
	}{
		{floor: 0, floorSet: false, chain: 4, issue: 5, newFloor: 4},
		// the pool didn't forge, so the same number is reissued
		{floor: 4, floorSet: true, chain: 4, issue: 5, newFloor: 4},
		{floor: 4, floorSet: true, chain: 5, issue: 6, newFloor: 5},
		{floor: 5, floorSet: true, chain: 4, fail: true},
		{floor: 0, floorSet: true, chain: ^uint64(0), fail: true},
	} {
		issue, newFloor, err := nextOpCert(c.floor, c.floorSet, c.chain)

		if c.fail {
			if err == nil {
				t.Errorf("%+v: allowed", c)
			}

			continue
		}

		if err != nil || issue != c.issue || newFloor != c.newFloor {
			t.Errorf("%+v: got (%d, %d, %v)", c, issue, newFloor, err)
		}
	}
}
