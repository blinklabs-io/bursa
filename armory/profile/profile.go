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

// Package profile defines signing profiles, one pool on one network, and the
// SE050 object ID layout they use.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxSlot is the highest profile slot.
const MaxSlot = 31

// IdentityKeyID holds the device identity key that signs key inventories.
const IdentityKeyID uint32 = 0x20e50020

// Object ID bases, offset by profile slot. Cold keys live at
// 0x20e50010-0x20e5001f and are shared between profiles by reference.
const (
	ownerKeyBase uint32 = 0x20e50100
	feeKeyBase   uint32 = 0x20e50200
	recordBase   uint32 = 0x20e50300
)

// Profile is one pool on one network. The device can't tell networks apart,
// so the name is an operator label that selects state and rules.
type Profile struct {
	// Name labels the profile, e.g. "otg@preview".
	Name string `json:"name"`
	// NetworkID is the address network bit: 0 testnet, 1 mainnet.
	NetworkID uint8 `json:"network_id"`
	// Slot selects this profile's owner, fee and record object IDs.
	Slot uint8 `json:"slot"`
	// ColdKeyID is the SE050 object holding the pool cold key.
	ColdKeyID uint32 `json:"cold_key_id"`
	// FloorSet reports whether OpCertFloor has been initialised.
	FloorSet bool `json:"floor_set"`
	// OpCertFloor is the highest on-chain opcert counter ever reported.
	OpCertFloor uint64 `json:"opcert_floor"`
	// MaxFee caps the fee of any body the device signs, in lovelace. Zero
	// selects DefaultMaxFee.
	MaxFee uint64 `json:"max_fee,omitempty"`
}

// DefaultMaxFee is the fee cap when a profile sets none: 2 ADA.
const DefaultMaxFee uint64 = 2_000_000

// FeeCap returns the highest fee this profile allows.
func (p Profile) FeeCap() uint64 {
	if p.MaxFee == 0 {
		return DefaultMaxFee
	}

	return p.MaxFee
}

// OwnerKeyID returns the object holding this profile's owner stake key.
func (p Profile) OwnerKeyID() uint32 { return ownerKeyBase + uint32(p.Slot) }

// FeeKeyID returns the object holding this profile's fee wallet key.
func (p Profile) FeeKeyID() uint32 { return feeKeyBase + uint32(p.Slot) }

// RecordID returns the binary object holding this profile record.
func (p Profile) RecordID() uint32 { return recordBase + uint32(p.Slot) }

func (p Profile) validate() error {
	switch {
	case p.Name == "":
		return errors.New("profile: empty name")
	case p.NetworkID > 1:
		return fmt.Errorf("profile: invalid network id %d", p.NetworkID)
	case p.Slot > MaxSlot:
		return fmt.Errorf("profile: invalid slot %d", p.Slot)
	}

	return nil
}

// Encode serializes a profile record.
func Encode(p Profile) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	return json.Marshal(p)
}

// Decode parses a profile record, rejecting unknown fields and trailing data.
func Decode(b []byte) (p Profile, err error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	if err = dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("profile: %w", err)
	}

	if _, err = dec.Token(); err != io.EOF {
		return Profile{}, errors.New("profile: trailing data")
	}

	if err = p.validate(); err != nil {
		return Profile{}, err
	}

	return p, nil
}
