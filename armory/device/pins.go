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
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/armory/profile"
)

// PinsRequest sets or replaces the registration pins of a profile: the VRF
// key hash and metadata hash its pool registrations must name, the digest of
// their relays and metadata URL (policy.RelaysDigest), and bounds for pledge,
// cost and margin. Hashes are 32 bytes in hex, the relays digest 20. An empty
// RelaysDigest leaves the relays, metadata URL and metadata hash unpinned, so
// registrations may change them; MetadataHash must then be empty too. With a
// RelaysDigest, an empty MetadataHash pins the absence of metadata. Bounds
// are inclusive; the margin bound is MarginMaxNum/MarginMaxDen.
type PinsRequest struct {
	HostAuth
	Profile      string `json:"profile"`
	VRFKeyHash   string `json:"vrf_key_hash"`
	MetadataHash string `json:"metadata_hash,omitempty"`
	PledgeMin    uint64 `json:"pledge_min"`
	PledgeMax    uint64 `json:"pledge_max"`
	CostMax      uint64 `json:"cost_max"`
	MarginMaxNum uint64 `json:"margin_max_num"`
	MarginMaxDen uint64 `json:"margin_max_den"`
	RelaysDigest string `json:"relays_digest"`
}

// PinsResponse confirms the stored pins.
type PinsResponse struct {
	Profile string      `json:"profile"`
	Pins    PinsRequest `json:"pins"`
}

// parseHex fills dst from v, which must be exactly len(dst) bytes of hex.
func parseHex(name, v string, dst []byte) error {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != len(dst) {
		return fmt.Errorf("%s must be %d bytes of hex", name, len(dst))
	}

	copy(dst, b)

	return nil
}

// pinsFor returns the registration pins stored for p. A profile with no pins
// object has none, and its registrations keep the unpinned checks. An object
// that cannot be read or decoded is an error, never "no pins": otherwise a
// damaged object would lift the pins.
func (s *Service) pinsFor(p profile.Profile) (*profile.Pins, error) {
	ok, err := s.chip.Exists(p.PinsID())
	if err != nil {
		s.logf("exist check %#08x: %v", p.PinsID(), err)
		return nil, errDevice
	}

	if !ok {
		return nil, nil
	}

	b, err := s.chip.ReadBinary(p.PinsID())
	if err != nil {
		s.logf("read pins %q: %v", p.Name, err)
		return nil, errDevice
	}

	pins, err := profile.DecodePins(b)
	if err != nil {
		s.logf("pins %q: invalid object: %v", p.Name, err)
		return nil, errors.New(
			"registration pins are unreadable; provision them again",
		)
	}

	return &pins, nil
}

// pinsState describes a profile's pins for the startup report: "set", "set,
// relays and metadata not pinned", "none", or "unreadable" for an object that
// cannot be decoded, which refuses signing.
func pinsState(chip Chip, p profile.Profile) string {
	ok, err := chip.Exists(p.PinsID())
	if err != nil {
		return "unreadable"
	}

	if !ok {
		return "none"
	}

	var pins profile.Pins

	b, err := chip.ReadBinary(p.PinsID())
	if err == nil {
		pins, err = profile.DecodePins(b)
	}

	if err != nil {
		return "unreadable"
	}

	if !pins.PinRelays {
		return "set, relays and metadata not pinned"
	}

	return "set"
}

// setPins sets or replaces a profile's registration pins. It is a deliberate
// provisioning action, so the pins cannot be changed from inside a
// transaction.
func (s *Service) setPins(req PinsRequest) (PinsResponse, error) {
	p, err := s.profileFor(req.Profile)
	if err != nil {
		return PinsResponse{}, err
	}

	// a misplaced record's pins object is another slot's, so pins are
	// refused while any record is unreadable or inconsistent, as provisioning
	// is
	if len(s.badSlots) > 0 {
		return PinsResponse{}, errors.New(
			"a profile record is unreadable or inconsistent; pins are refused until it is repaired",
		)
	}

	var pins profile.Pins

	if err = parseHex("vrf_key_hash", req.VRFKeyHash, pins.VRFKeyHash[:]); err != nil {
		return PinsResponse{}, err
	}

	// relays and metadata are pinned together, by the relays digest: without
	// one, registrations may change both
	pins.PinRelays = req.RelaysDigest != ""

	if !pins.PinRelays && req.MetadataHash != "" {
		return PinsResponse{}, errors.New(
			"metadata_hash needs relays_digest: metadata is pinned only with the relays",
		)
	}

	if pins.PinRelays {
		if err = parseHex("relays_digest", req.RelaysDigest, pins.RelaysDigest[:]); err != nil {
			return PinsResponse{}, err
		}
	}

	if req.MetadataHash != "" {
		pins.MetadataHash = new([32]byte)

		if err = parseHex("metadata_hash", req.MetadataHash, pins.MetadataHash[:]); err != nil {
			return PinsResponse{}, err
		}
	}

	pins.PledgeMin, pins.PledgeMax, pins.CostMax = req.PledgeMin, req.PledgeMax, req.CostMax
	pins.MarginMaxNum, pins.MarginMaxDen = req.MarginMaxNum, req.MarginMaxDen

	b, err := profile.EncodePins(pins)
	if err != nil {
		return PinsResponse{}, err
	}

	if err = s.chip.WriteBinary(p.PinsID(), b); err != nil {
		s.logf("write pins %q: %v", p.Name, err)
		return PinsResponse{}, errDevice
	}

	meta, relays := "none", "not pinned"
	if pins.MetadataHash != nil {
		meta = hex.EncodeToString(pins.MetadataHash[:])
	}

	if pins.PinRelays {
		relays = hex.EncodeToString(pins.RelaysDigest[:])
	} else {
		meta = "not pinned"
	}

	s.logf(
		"registration pins %q set: vrf %s metadata %s relays %s pledge %d-%d cost <=%d margin <=%d/%d",
		p.Name,
		hex.EncodeToString(pins.VRFKeyHash[:]),
		meta,
		relays,
		pins.PledgeMin,
		pins.PledgeMax,
		pins.CostMax,
		pins.MarginMaxNum,
		pins.MarginMaxDen,
	)

	req.Profile = p.Name

	// echo the pins, not the request's authentication
	req.HostAuth = HostAuth{}

	return PinsResponse{Profile: p.Name, Pins: req}, nil
}
