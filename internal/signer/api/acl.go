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

package api

import "github.com/blinklabs-io/bursa/internal/signer/backend"

// CallerACL maps authenticated JWT subjects to the key hashes they may use.
// A nil or empty ACL is unrestricted (single trust domain). When restricted,
// unlisted callers are denied all keys (fail closed).
type CallerACL struct {
	byCaller map[string]map[backend.KeyHash]bool
}

// NewCallerACL builds an ACL from subject → permitted key hashes.
func NewCallerACL(entries map[string][]backend.KeyHash) *CallerACL {
	if len(entries) == 0 {
		return &CallerACL{}
	}
	m := make(map[string]map[backend.KeyHash]bool, len(entries))
	for sub, hashes := range entries {
		set := make(map[backend.KeyHash]bool, len(hashes))
		for _, h := range hashes {
			set[h] = true
		}
		m[sub] = set
	}
	return &CallerACL{byCaller: m}
}

// Restricted reports whether the ACL constrains callers at all.
func (a *CallerACL) Restricted() bool { return a != nil && len(a.byCaller) > 0 }

// Allows reports whether caller may use the key. Unrestricted ACLs allow all.
func (a *CallerACL) Allows(caller string, hash backend.KeyHash) bool {
	// Explicit nil/empty guard (rather than delegating to Restricted) so the
	// non-nil receiver is provable at the byCaller dereference below.
	if a == nil || len(a.byCaller) == 0 {
		return true
	}
	return a.byCaller[caller][hash]
}
