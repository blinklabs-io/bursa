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
	"encoding/binary"
	"errors"
	"fmt"
)

// PinsSize is the fixed size of an encoded Pins object, zero padded. It fits
// in a single binary write APDU, so replacing the pins rewrites the object
// in place.
const PinsSize = 128

// pinsVersion is the first byte of an encoded Pins object. A decoder refuses
// any other value, so a later layout cannot be read as this one.
const pinsVersion = 1

// pinsBase is the first pins object ID, offset by profile slot. 0x20e50400
// is deliberately left outside the armory ranges.
const pinsBase uint32 = 0x20e50500

// pinsFlagMetadata marks an encoded Pins that pins a metadata hash.
const pinsFlagMetadata = 1

// pinsFlagRelays marks an encoded Pins that pins the relays, the metadata
// URL and the metadata hash or its absence.
const pinsFlagRelays = 2

// RelaysDigestSize is the size of the digest that pins a registration's
// relays and metadata URL.
const RelaysDigestSize = 20

// pinsUsed is how many bytes of an encoded Pins carry fields; the rest is
// zero padding.
const pinsUsed = 126

// PinsID returns the binary object holding this profile's registration pins.
// The object is separate from the profile record, which has no room left,
// and absent for a profile whose registrations are not pinned.
func (p Profile) PinsID() uint32 { return pinsBase + uint32(p.Slot) }

// Pins are the pool registration parameters a profile's registrations must
// match: the VRF key hash exactly and pledge, cost and margin within bounds,
// and, when PinRelays is set, the relays, metadata URL and metadata hash
// exactly.
type Pins struct {
	// VRFKeyHash is the VRF key hash every registration must name.
	VRFKeyHash [32]byte
	// PinRelays pins MetadataHash and RelaysDigest. Without it registrations
	// may change their relays and metadata, so they can be updated without
	// provisioning new pins, and both fields must be empty.
	PinRelays bool
	// MetadataHash is the pool metadata hash every registration must name.
	// Nil pins the absence of metadata, when PinRelays is set.
	MetadataHash *[32]byte
	// PledgeMin and PledgeMax bound the pledge, inclusive.
	PledgeMin, PledgeMax uint64
	// CostMax bounds the fixed cost, inclusive.
	CostMax uint64
	// MarginMaxNum / MarginMaxDen bound the margin, inclusive.
	MarginMaxNum, MarginMaxDen uint64
	// RelaysDigest pins the relays, in order, and the metadata URL every
	// registration must carry: policy.RelaysDigest of them.
	RelaysDigest [RelaysDigestSize]byte
}

func (p Pins) validate() error {
	switch {
	case p.PledgeMin > p.PledgeMax:
		return errors.New("pins: pledge minimum above maximum")
	case p.MarginMaxDen == 0:
		return errors.New("pins: margin maximum has a zero denominator")
	case p.MarginMaxNum > p.MarginMaxDen:
		return errors.New("pins: margin maximum above 1")
	case !p.PinRelays && (p.MetadataHash != nil || p.RelaysDigest != [RelaysDigestSize]byte{}):
		return errors.New("pins: metadata or relays digest without pinned relays")
	}

	return nil
}

// EncodePins serializes pins to exactly PinsSize bytes: version, flags
// (pinsFlagMetadata, pinsFlagRelays), VRF key hash, metadata hash (zero when
// not pinned), pledge minimum and maximum,
// cost maximum, margin maximum numerator and denominator (big endian), relays
// digest, then zero padding.
func EncodePins(p Pins) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	b := make([]byte, PinsSize)
	b[0] = pinsVersion

	copy(b[2:34], p.VRFKeyHash[:])

	if p.PinRelays {
		b[1] |= pinsFlagRelays
	}

	if p.MetadataHash != nil {
		b[1] |= pinsFlagMetadata
		copy(b[34:66], p.MetadataHash[:])
	}

	for i, v := range []uint64{p.PledgeMin, p.PledgeMax, p.CostMax, p.MarginMaxNum, p.MarginMaxDen} {
		binary.BigEndian.PutUint64(b[66+8*i:], v)
	}

	copy(b[106:pinsUsed], p.RelaysDigest[:])

	return b, nil
}

// DecodePins parses a pins object, rejecting another version, unknown flags,
// a stray metadata hash, a metadata hash or relays digest without pinned
// relays, non-zero padding and a wrong size.
func DecodePins(b []byte) (p Pins, err error) {
	if len(b) != PinsSize {
		return Pins{}, fmt.Errorf("pins: object is %d bytes, want %d", len(b), PinsSize)
	}

	if b[0] != pinsVersion {
		return Pins{}, fmt.Errorf("pins: unsupported version %d", b[0])
	}

	if b[1]&^(pinsFlagMetadata|pinsFlagRelays) != 0 {
		return Pins{}, errors.New("pins: unknown flags")
	}

	if !bytes.Equal(b[pinsUsed:], make([]byte, PinsSize-pinsUsed)) {
		return Pins{}, errors.New("pins: non-zero padding")
	}

	copy(p.VRFKeyHash[:], b[2:34])
	p.PinRelays = b[1]&pinsFlagRelays != 0

	if b[1]&pinsFlagMetadata != 0 {
		p.MetadataHash = new([32]byte)
		copy(p.MetadataHash[:], b[34:66])
	} else if !bytes.Equal(b[34:66], make([]byte, 32)) {
		return Pins{}, errors.New("pins: metadata hash without its flag")
	}

	p.PledgeMin = binary.BigEndian.Uint64(b[66:])
	p.PledgeMax = binary.BigEndian.Uint64(b[74:])
	p.CostMax = binary.BigEndian.Uint64(b[82:])
	p.MarginMaxNum = binary.BigEndian.Uint64(b[90:])
	p.MarginMaxDen = binary.BigEndian.Uint64(b[98:])
	copy(p.RelaysDigest[:], b[106:pinsUsed])

	if err = p.validate(); err != nil {
		return Pins{}, err
	}

	return p, nil
}
