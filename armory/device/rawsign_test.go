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
	"bytes"
	"crypto/ed25519"
	"testing"
)

// The unfiltered testnet /sign must never use a key a mainnet profile can
// occupy, whether or not a profile record names it and whether or not the
// profiles were loaded.
func TestSignRawNeverUsesColdKey(t *testing.T) {
	t.Parallel()

	if RawSignKeyID >= coldKeyFirst && RawSignKeyID <= coldKeyLast {
		t.Errorf("raw key %#08x is inside the cold key range", RawSignKeyID)
	}

	// a mainnet cold key imported into the first slot, with no profile record
	// and no SetChip: the state after a legacy /provision or /provision/cold
	chip := newFakeChip()
	cold := chip.keys[coldKeyFirst].Public().(ed25519.PublicKey)
	msg := []byte("raw message")

	sig, err := SignRaw(chip, msg)
	if err != nil {
		t.Fatal(err)
	}

	if ed25519.Verify(cold, msg, sig) {
		t.Fatal("raw signature verifies under the first cold key slot")
	}

	pub, err := RawPublicKey(chip)
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("raw signature does not verify under the raw public key")
	}

	// the key persists across calls
	pub2, _ := RawPublicKey(chip)
	if !bytes.Equal(pub, pub2) {
		t.Fatal("raw public key changed between calls")
	}

	// a failed chip is an error, not a fallback to another key
	chip.failExists = true
	if _, err := SignRaw(chip, msg); err == nil {
		t.Fatal("signed with an unreadable chip")
	}
}

// The raw key is wiped with the bring-up objects and disjoint from every
// other armory object.
func TestRawSignKeyIsBringupObject(t *testing.T) {
	t.Parallel()

	if RawSignKeyID < bringupFirst || RawSignKeyID > bringupLast {
		t.Fatalf("raw key %#08x outside the bring-up range", RawSignKeyID)
	}

	if RawSignKeyID == 0x20e50001 || RawSignKeyID == 0x20e50002 {
		t.Fatal("raw key collides with a bring-up test object")
	}
}

// The log entry for an unfiltered signature names the raw key's role, not a
// cold key, since no cold key makes it.
func TestRecordRawRoleIsRaw(t *testing.T) {
	t.Parallel()

	s, _, l, _ := loggedService(t)

	if err := s.RecordRaw([]byte("raw message")); err != nil {
		t.Fatal(err)
	}

	if len(l.records) != 1 || l.records[0].Role != rawSignRole {
		t.Fatalf("records %+v", l.records)
	}
}
