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

		for _, id := range []uint32{p.OwnerKeyID(), p.FeeKeyID(), p.RecordID()} {
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
