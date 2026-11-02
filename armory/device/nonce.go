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

// nonceRingSize is how many recent request nonces are remembered.
const nonceRingSize = 1024

// nonceRing refuses a nonce seen among the last nonceRingSize requests.
type nonceRing struct {
	seen  map[string]bool
	order [nonceRingSize]string
	next  int
}

// add records n, reporting false if it was already recorded.
func (r *nonceRing) add(n []byte) bool {
	if r.seen == nil {
		r.seen = make(map[string]bool, nonceRingSize)
	}

	k := string(n)

	if r.seen[k] {
		return false
	}

	if old := r.order[r.next]; old != "" {
		delete(r.seen, old)
	}

	r.order[r.next] = k
	r.next = (r.next + 1) % nonceRingSize
	r.seen[k] = true

	return true
}
