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

package backend

import (
	"crypto/ed25519"
	"testing"
)

func TestHashPublicKey_And_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	h := HashPublicKey(pub)
	s := h.String()
	if len(s) != 56 {
		t.Fatalf("expected 56 hex chars (28 bytes), got %d", len(s))
	}
	parsed, err := ParseKeyHash(s)
	if err != nil {
		t.Fatalf("ParseKeyHash: %v", err)
	}
	if parsed != h {
		t.Fatalf("round-trip mismatch: %s != %s", parsed, h)
	}
}

func TestHashPublicKey_PanicsOnWrongLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for malformed public key")
		}
	}()
	HashPublicKey([]byte{1, 2, 3})
}

func TestParseKeyHash_BadLength(t *testing.T) {
	if _, err := ParseKeyHash("deadbeef"); err == nil {
		t.Fatalf("expected error for short hash")
	}
}

func TestKeyType_Valid(t *testing.T) {
	if !KeyType("payment").Valid() {
		t.Fatalf("payment should be valid")
	}
	if KeyType("bogus").Valid() {
		t.Fatalf("bogus should be invalid")
	}
}
