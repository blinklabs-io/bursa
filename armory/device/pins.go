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
// key hash and metadata hash its pool registrations must name, and bounds for
// pledge, cost and margin. Hashes are 32 bytes in hex. An empty MetadataHash
// pins the absence of metadata. Bounds are inclusive; the margin bound is
// MarginMaxNum/MarginMaxDen.
type PinsRequest struct {
	Profile      string `json:"profile"`
	VRFKeyHash   string `json:"vrf_key_hash"`
	MetadataHash string `json:"metadata_hash,omitempty"`
	PledgeMin    uint64 `json:"pledge_min"`
	PledgeMax    uint64 `json:"pledge_max"`
	CostMax      uint64 `json:"cost_max"`
	MarginMaxNum uint64 `json:"margin_max_num"`
	MarginMaxDen uint64 `json:"margin_max_den"`
}

// PinsResponse confirms the stored pins.
type PinsResponse struct {
	Profile string      `json:"profile"`
	Pins    PinsRequest `json:"pins"`
}

func parseHash32(name, v string) ([32]byte, error) {
	var h [32]byte

	b, err := hex.DecodeString(v)
	if err != nil || len(b) != len(h) {
		return h, fmt.Errorf("%s must be 32 bytes of hex", name)
	}

	copy(h[:], b)

	return h, nil
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
		return nil, errors.New("registration pins are unreadable; provision them again")
	}

	return &pins, nil
}

// pinsState describes a profile's pins for the startup report: "set", "none",
// or "unreadable" for an object that cannot be decoded, which refuses signing.
func pinsState(chip Chip, p profile.Profile) string {
	ok, err := chip.Exists(p.PinsID())
	if err != nil {
		return "unreadable"
	}

	if !ok {
		return "none"
	}

	b, err := chip.ReadBinary(p.PinsID())
	if err == nil {
		_, err = profile.DecodePins(b)
	}

	if err != nil {
		return "unreadable"
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

	var pins profile.Pins

	if pins.VRFKeyHash, err = parseHash32("vrf_key_hash", req.VRFKeyHash); err != nil {
		return PinsResponse{}, err
	}

	if req.MetadataHash != "" {
		h, err := parseHash32("metadata_hash", req.MetadataHash)
		if err != nil {
			return PinsResponse{}, err
		}

		pins.MetadataHash = &h
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

	meta := "none"
	if pins.MetadataHash != nil {
		meta = hex.EncodeToString(pins.MetadataHash[:])
	}

	s.logf("registration pins %q set: vrf %s metadata %s pledge %d-%d cost <=%d margin <=%d/%d",
		p.Name, hex.EncodeToString(pins.VRFKeyHash[:]), meta,
		pins.PledgeMin, pins.PledgeMax, pins.CostMax, pins.MarginMaxNum, pins.MarginMaxDen)

	req.Profile = p.Name

	return PinsResponse{Profile: p.Name, Pins: req}, nil
}
