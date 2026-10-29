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

package profile

import (
	"strings"
	"testing"
)

func testProfile() Profile {
	return Profile{
		Name:        "otg@preview",
		NetworkID:   0,
		Slot:        0,
		ColdKeyID:   0x20e50010,
		FloorSet:    true,
		OpCertFloor: 3,
		// testnet key-hash reward address
		RewardAccount: "e0" + strings.Repeat("ab", 28),
	}
}

func TestProfileRoundTrip(t *testing.T) {
	want := testProfile()

	b, err := Encode(want)

	if err != nil {
		t.Fatal(err)
	}

	got, err := Decode(b)

	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDecodeRejects(t *testing.T) {
	for name, input := range map[string]string{
		"unknown field": `{"name":"a","network_id":0,"slot":0,"cold_key_id":1,"extra":1}`,
		"network 2":     `{"name":"a","network_id":2,"slot":0,"cold_key_id":1}`,
		"slot 32":       `{"name":"a","network_id":0,"slot":32,"cold_key_id":1}`,
		"empty name":    `{"name":"","network_id":0,"slot":0,"cold_key_id":1}`,
		"trailing data": `{"name":"a","network_id":0,"slot":0,"cold_key_id":1}{}`,
	} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestObjectIDsDisjoint(t *testing.T) {
	reserved := map[uint32]string{
		0x20e50001:    "bring-up generated",
		0x20e50002:    "bring-up imported",
		IdentityKeyID: "identity",
	}

	for id := uint32(0x20e50010); id <= 0x20e5001f; id++ {
		reserved[id] = "cold key"
	}

	seen := map[uint32]string{}

	for slot := uint8(0); slot <= MaxSlot; slot++ {
		p := Profile{Slot: slot}

		for _, id := range []uint32{p.OwnerKeyID(), p.RecordID()} {
			if what, ok := reserved[id]; ok {
				t.Fatalf("slot %d ID %#08x collides with %s", slot, id, what)
			}

			if _, ok := seen[id]; ok {
				t.Fatalf("slot %d ID %#08x used twice", slot, id)
			}

			seen[id] = "profile"
		}
	}
}

func TestRewardAccountRules(t *testing.T) {
	base := testProfile()

	for name, ra := range map[string]string{
		"mainnet header on testnet": "e1" + strings.Repeat("ab", 28),
		"payment address":           "60" + strings.Repeat("ab", 28),
		"short":                     "e0" + strings.Repeat("ab", 27),
		"not hex":                   "e0" + strings.Repeat("zz", 28),
	} {
		p := base
		p.RewardAccount = ra

		if _, err := Encode(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	for _, ra := range []string{"", "f0" + strings.Repeat("ab", 28)} {
		p := base
		p.RewardAccount = ra

		if _, err := Encode(p); err != nil {
			t.Errorf("reward account %q refused: %v", ra, err)
		}
	}

	if b, ok := base.RewardAddress(); !ok || len(b) != 29 || b[0] != 0xe0 {
		t.Fatalf("RewardAddress = % x, %v", b, ok)
	}

	if _, ok := (Profile{}).RewardAddress(); ok {
		t.Fatal("unset reward account reported as set")
	}
}

func TestBoundsCheckedWithRewardAccount(t *testing.T) {
	slot := testProfile()
	slot.Slot = MaxSlot + 1

	network := testProfile()
	network.NetworkID = 2
	network.RewardAccount = "e2" + strings.Repeat("ab", 28)

	for name, p := range map[string]Profile{"slot": slot, "network": network} {
		if _, err := Encode(p); err == nil {
			t.Errorf("%s out of range accepted with a reward account", name)
		}
	}
}

func TestEncodeFixedSize(t *testing.T) {
	small := testProfile()
	large := Profile{
		Name:          strings.Repeat("n", MaxNameLen),
		NetworkID:     1,
		Slot:          MaxSlot,
		ColdKeyID:     ^uint32(0),
		FloorSet:      true,
		OpCertFloor:   ^uint64(0),
		RewardAccount: "f1" + strings.Repeat("ff", 28),
	}

	for _, p := range []Profile{small, large} {
		b, err := Encode(p)

		if err != nil {
			t.Fatal(err)
		}

		if len(b) != RecordSize {
			t.Fatalf("record is %d bytes, want %d", len(b), RecordSize)
		}

		if got, err := Decode(b); err != nil || got != p {
			t.Fatalf("round trip %+v, %v", got, err)
		}
	}

	// one APDU writes the whole record, so a write is never split
	if RecordSize > 0xe0 {
		t.Fatalf("RecordSize %d exceeds one binary write chunk", RecordSize)
	}
}

func TestNameRules(t *testing.T) {
	for _, name := range []string{strings.Repeat("n", MaxNameLen+1), "otg preview", "pool\"x", "ünicode"} {
		if _, err := Encode(Profile{Name: name}); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}

	if _, err := Encode(Profile{Name: "otg@prime-mainnet_2.x"}); err != nil {
		t.Fatal(err)
	}
}
