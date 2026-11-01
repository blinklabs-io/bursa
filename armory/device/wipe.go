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
	"net/http"
	"strings"

	"github.com/blinklabs-io/bursa/armory/profile"
)

// Armory object ranges the profile package does not name: the bring-up key
// tests' transient objects, and the fee wallet keys of early builds.
const (
	bringupFirst uint32 = 0x20e50001
	bringupLast  uint32 = 0x20e5000f
	feeKeyFirst  uint32 = 0x20e50200
	feeKeyLast   uint32 = 0x20e5021f
)

var errWipeConfirm = errors.New("identity_public_key does not match the device identity key")

// WipeDeviceRequest confirms a device wipe with the device identity public
// key in hex, as Bursa pins it. A device with no identity key takes an empty
// value.
type WipeDeviceRequest struct {
	IdentityPublicKey string `json:"identity_public_key"`
}

// WipeProfileRequest confirms the removal of one profile, as
// WipeDeviceRequest.
type WipeProfileRequest struct {
	IdentityPublicKey string `json:"identity_public_key"`
	Profile           string `json:"profile"`
}

// WipeResponse lists the armory objects present, or the ones a wipe deleted,
// as hex object IDs.
type WipeResponse struct {
	Objects []string `json:"objects,omitempty"`
	Deleted []string `json:"deleted,omitempty"`
}

// WipeHandler serves only the wipe endpoints, for the wipe firmware. Neither
// the signing nor the provisioning firmware serves them. As with the
// provisioning endpoints, requests are not host-key authenticated: the wipe
// image must be loaded onto the board, and the identity public key only
// confirms which device is meant. A wipe that fails reports no partial list;
// the request is sent again, and /wipe/objects lists what remains.
func (s *Service) WipeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /wipe/objects", handle(s, func(struct{}) (WipeResponse, error) {
		ids, err := s.armoryObjects()
		return WipeResponse{Objects: hexIDs(ids)}, err
	}))
	mux.HandleFunc("POST /wipe/device", handle(s, s.wipeDevice))
	mux.HandleFunc("POST /wipe/profile", handle(s, s.wipeProfile))
	mux.HandleFunc("POST /wipe/signlog", handle(s, s.wipeSignLog))

	return mux
}

// armoryIDs lists every object ID the armory may have created, the identity
// key last, so a wipe in this order can be retried with the same
// confirmation.
func armoryIDs() []uint32 {
	var ids []uint32

	add := func(first, last uint32) {
		for id := first; id <= last; id++ {
			ids = append(ids, id)
		}
	}

	add(bringupFirst, bringupLast)
	add(coldKeyFirst, coldKeyLast)
	ids = append(ids, hostKeysID)

	for slot := uint8(0); slot <= profile.MaxSlot; slot++ {
		ids = append(ids, profile.Profile{Slot: slot}.OwnerKeyID())
	}

	add(feeKeyFirst, feeKeyLast)

	for slot := uint8(0); slot <= profile.MaxSlot; slot++ {
		ids = append(ids, profile.Profile{Slot: slot}.RecordID())
	}

	// the signing log head is chained to the identity key, so it goes with it
	return append(ids, profile.SignLogHeadID, profile.IdentityKeyID)
}

// armoryObjects returns the armory objects present on the chip.
func (s *Service) armoryObjects() ([]uint32, error) {
	var present []uint32

	for _, id := range armoryIDs() {
		ok, err := s.chip.Exists(id)
		if err != nil {
			s.logf("exist check %#08x: %v", id, err)
			return nil, errDevice
		}

		if ok {
			present = append(present, id)
		}
	}

	return present, nil
}

// confirm checks a wipe request names this device: its identity public key,
// or nothing when it has no identity key.
func (s *Service) confirm(identity string) error {
	ok, err := s.chip.Exists(profile.IdentityKeyID)
	if err != nil {
		s.logf("exist check %#08x: %v", profile.IdentityKeyID, err)
		return errDevice
	}

	if !ok {
		if identity != "" {
			return errWipeConfirm
		}

		return nil
	}

	pub, err := s.publicKey(profile.IdentityKeyID)
	if err != nil {
		return err
	}

	if !strings.EqualFold(identity, hex.EncodeToString(pub)) {
		return errWipeConfirm
	}

	return nil
}

// remove deletes the objects that exist, in order. An object already gone
// counts as deleted, so a wipe stopped part way finishes when sent again.
func (s *Service) remove(ids []uint32) ([]uint32, error) {
	var deleted []uint32

	for _, id := range ids {
		ok, err := s.chip.Exists(id)
		if err != nil {
			s.logf("exist check %#08x: %v", id, err)
			return nil, errDevice
		}

		if !ok {
			continue
		}

		if err = s.chip.Delete(id); err != nil {
			s.logf("wipe: delete %#08x: %v", id, err)
			return nil, fmt.Errorf("%w: deleting %#08x; send the request again", errDevice, id)
		}

		s.logf("wipe: deleted %#08x", id)
		deleted = append(deleted, id)
	}

	return deleted, nil
}

// wipeDevice deletes every armory object: keys, profiles, host keys, the
// signing log head and the identity key. Objects outside the armory ranges
// are left alone.
func (s *Service) wipeDevice(req WipeDeviceRequest) (WipeResponse, error) {
	if err := s.confirm(req.IdentityPublicKey); err != nil {
		return WipeResponse{}, err
	}

	ids, err := s.armoryObjects()
	if err != nil {
		return WipeResponse{}, err
	}

	deleted, err := s.remove(ids)
	if err != nil {
		return WipeResponse{}, err
	}

	s.profiles = map[string]profile.Profile{}
	s.hostKeys, s.hostKeysBad = nil, false
	s.logf("wipe: device wiped, %d objects deleted", len(deleted))

	return WipeResponse{Deleted: hexIDs(deleted)}, nil
}

// wipeSignLog deletes only the signing log head, so the signing firmware
// starts a new log on a zeroed card under the same identity key. Every entry
// on the old card stays verifiable with signlog-verify -image.
func (s *Service) wipeSignLog(req WipeDeviceRequest) (WipeResponse, error) {
	if err := s.confirm(req.IdentityPublicKey); err != nil {
		return WipeResponse{}, err
	}

	deleted, err := s.remove([]uint32{profile.SignLogHeadID})
	if err != nil {
		return WipeResponse{}, err
	}

	s.logf("wipe: signing log head reset")

	return WipeResponse{Deleted: hexIDs(deleted)}, nil
}

// wipeProfile deletes one profile: its owner key, its cold key unless another
// profile names it, and its record last, so a removal stopped part way can be
// sent again by name. The slot and the cold key object are free again.
func (s *Service) wipeProfile(req WipeProfileRequest) (WipeResponse, error) {
	if err := s.confirm(req.IdentityPublicKey); err != nil {
		return WipeResponse{}, err
	}

	p, ok := s.profiles[req.Profile]
	if !ok {
		return WipeResponse{}, errUnknown
	}

	// an unreadable, misplaced or duplicate record may name the same cold
	// key or this profile's objects, so ownership cannot be established
	if len(s.badSlots) > 0 {
		return WipeResponse{}, errors.New("a profile record is unreadable or inconsistent; wipe the device instead")
	}

	// a stored record may name any object; delete only an armory cold key
	if p.ColdKeyID < coldKeyFirst || p.ColdKeyID > coldKeyLast {
		return WipeResponse{}, errors.New("profile cold key id outside the cold key range; wipe the device instead")
	}

	ids := []uint32{p.OwnerKeyID()}
	shared := false

	for _, other := range s.profiles {
		if other.Name != p.Name && other.ColdKeyID == p.ColdKeyID {
			shared = true
		}
	}

	if !shared {
		ids = append(ids, p.ColdKeyID)
	}

	deleted, err := s.remove(append(ids, p.RecordID()))
	if err != nil {
		return WipeResponse{}, err
	}

	delete(s.profiles, p.Name)
	s.logf("wipe: profile %q slot %d removed", p.Name, p.Slot)

	return WipeResponse{Deleted: hexIDs(deleted)}, nil
}

func hexIDs(ids []uint32) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = fmt.Sprintf("%#08x", id)
	}

	return out
}
