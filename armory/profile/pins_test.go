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
	"bytes"
	"testing"
)

func testPins() Pins {
	meta := [32]byte{0x33}

	return Pins{
		VRFKeyHash: [32]byte{0x11}, PinRelays: true, MetadataHash: &meta,
		PledgeMin: 1, PledgeMax: 500, CostMax: 170, MarginMaxNum: 1, MarginMaxDen: 10,
		RelaysDigest: [RelaysDigestSize]byte{0x55, 19: 0x66},
	}
}

func TestPinsRoundTrip(t *testing.T) {
	t.Parallel()

	for name, p := range map[string]Pins{
		"metadata":                     testPins(),
		"no metadata":                  {VRFKeyHash: [32]byte{9}, PinRelays: true, PledgeMax: 1, MarginMaxNum: 0, MarginMaxDen: 1},
		"relays and metadata unpinned": {VRFKeyHash: [32]byte{9}, PledgeMax: 1, MarginMaxNum: 0, MarginMaxDen: 1},
	} {
		b, err := EncodePins(p)
		if err != nil || len(b) != PinsSize {
			t.Fatalf("%s: encode: %d bytes, %v", name, len(b), err)
		}

		got, err := DecodePins(b)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}

		again, _ := EncodePins(got)
		if !bytes.Equal(again, b) || (got.MetadataHash == nil) != (p.MetadataHash == nil) || got.RelaysDigest != p.RelaysDigest || got.PinRelays != p.PinRelays {
			t.Errorf("%s: round trip changed the pins", name)
		}
	}
}

// TestPinsLayout pins the byte layout, so a change to it is a deliberate one.
func TestPinsLayout(t *testing.T) {
	t.Parallel()

	b, err := EncodePins(testPins())
	if err != nil {
		t.Fatal(err)
	}

	want := append([]byte{1, 3, 0x11}, make([]byte, 31)...)
	want = append(want, 0x33)
	want = append(want, make([]byte, 31)...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0xf4, 0, 0, 0, 0, 0, 0, 0, 170,
		0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 10)
	want = append(want, 0x55)
	want = append(want, make([]byte, 18)...)
	want = append(want, 0x66)
	want = append(want, make([]byte, PinsSize-len(want))...)

	if !bytes.Equal(b, want) {
		t.Errorf("layout:\n got %x\nwant %x", b, want)
	}
}

func TestPinsRejected(t *testing.T) {
	t.Parallel()

	good, _ := EncodePins(testPins())
	mut := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(good)) }

	for name, b := range map[string][]byte{
		"short":            good[:PinsSize-1],
		"long":             append(bytes.Clone(good), 0),
		"version":          mut(func(b []byte) []byte { b[0] = 2; return b }),
		"unknown flag":     mut(func(b []byte) []byte { b[1] = 7; return b }),
		"metadata no flag": mut(func(b []byte) []byte { b[1] = 2; return b }),
		// relays unpinned, but the metadata flag or the digest still set
		"metadata flag without relays": mut(func(b []byte) []byte { b[1] = 1; return b }),
		"digest without relays": mut(func(b []byte) []byte {
			b[1] = 0
			clear(b[34:66])

			return b
		}),
		"padding":          mut(func(b []byte) []byte { b[PinsSize-1] = 1; return b }),
		"first padding":    mut(func(b []byte) []byte { b[126] = 1; return b }),
		"pledge range":     mut(func(b []byte) []byte { b[66] = 1; return b }),
		"zero denominator": mut(func(b []byte) []byte { b[105] = 0; b[104] = 0; return b }),
	} {
		if _, err := DecodePins(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}

	for name, p := range map[string]Pins{
		"pledge":                    {PledgeMin: 2, PledgeMax: 1, MarginMaxDen: 1},
		"denominator":               {MarginMaxDen: 0},
		"margin":                    {MarginMaxNum: 2, MarginMaxDen: 1},
		"metadata, relays unpinned": {MetadataHash: new([32]byte), MarginMaxDen: 1},
		"digest, relays unpinned":   {RelaysDigest: [RelaysDigestSize]byte{1}, MarginMaxDen: 1},
	} {
		if _, err := EncodePins(p); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}

func TestPinsIDs(t *testing.T) {
	t.Parallel()

	seen := map[uint32]bool{}

	for slot := uint8(0); slot <= MaxSlot; slot++ {
		p := Profile{Slot: slot}
		for _, id := range []uint32{p.PinsID(), p.RecordID(), p.OwnerKeyID()} {
			if seen[id] {
				t.Fatalf("slot %d: object id %#x collides", slot, id)
			}

			seen[id] = true
		}
	}

	if id := (Profile{Slot: 0}).PinsID(); id != 0x20e50500 {
		t.Errorf("slot 0 pins id %#x", id)
	}
}
