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

import (
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

func TestCallerACL(t *testing.T) {
	var h1, h2 backend.KeyHash
	h1[0] = 1
	h2[0] = 2

	var nilACL *CallerACL
	if !nilACL.Allows("anyone", h1) {
		t.Fatal("nil ACL must be unrestricted")
	}
	if nilACL.Restricted() {
		t.Fatal("nil ACL must not be restricted")
	}
	empty := NewCallerACL(nil)
	if empty.Restricted() {
		t.Fatal("empty ACL must be unrestricted")
	}

	acl := NewCallerACL(map[string][]backend.KeyHash{"alice": {h1}})
	if !acl.Restricted() {
		t.Fatal("expected restricted")
	}
	if !acl.Allows("alice", h1) {
		t.Fatal("alice should have h1")
	}
	if acl.Allows("alice", h2) {
		t.Fatal("alice should not have h2")
	}
	if acl.Allows("bob", h1) {
		t.Fatal("unlisted caller should be denied")
	}

	// A subject explicitly listed with an empty key set must be locked out.
	carol := NewCallerACL(map[string][]backend.KeyHash{"carol": {}})
	if !carol.Restricted() {
		t.Fatal("expected restricted")
	}
	if carol.Allows("carol", h1) {
		t.Fatal("subject with empty keys list must be locked out")
	}
}
