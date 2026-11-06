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
// tests' transient objects and the testnet raw signing key, and the fee
// wallet keys of early builds.
const (
	bringupFirst uint32 = 0x20e50001
	bringupLast  uint32 = 0x20e5000f
	feeKeyFirst  uint32 = 0x20e50200
	feeKeyLast   uint32 = 0x20e5021f
)

var errWipeConfirm = errors.New(
	"identity_public_key does not match the device identity key",
)

// WipeDeviceRequest confirms a device wipe with the device identity public
// key in hex, as Bursa pins it. A device with no identity key takes an empty
// value.
type WipeDeviceRequest struct {
	IdentityPublicKey string `json:"identity_public_key"`
}

// WipeProfileRequest confirms the removal of one profile, as
// WipeDeviceRequest.
type WipeProfileRequest struct {
	HostAuth
	IdentityPublicKey string `json:"identity_public_key"`
	Profile           string `json:"profile"`
}

// WipeResponse lists the armory objects present, or the ones a wipe deleted,
// as hex object IDs.
type WipeResponse struct {
	Objects []string `json:"objects,omitempty"`
	Deleted []string `json:"deleted,omitempty"`
}

// WipeHandler serves only the wipe endpoints and the challenge endpoint, for
// the wipe firmware. Neither the signing nor the provisioning firmware serves
// them. Once a host key is registered, /wipe/profile and /wipe/signlog need a
// request signed by a host key of this build's network and chain, as the
// provisioning endpoints do, and the identity public key only confirms which
// device is meant. /wipe/device is confirmed by the identity public key
// alone, which is public: it is the way out when every host key is lost, and
// it deletes everything the armory holds. /wipe/objects only lists object
// IDs. A wipe that fails reports no partial list; the request is sent again,
// and /wipe/objects lists what remains.
func (s *Service) WipeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/challenge", handle(s, s.challenge))
	mux.HandleFunc(
		"POST /wipe/objects",
		handle(s, func(struct{}) (WipeResponse, error) {
			ids, err := s.armoryObjects()
			return WipeResponse{Objects: hexIDs(ids)}, err
		}),
	)
	mux.HandleFunc("POST /wipe/device", handle(s, s.wipeDevice))
	mux.HandleFunc(
		"POST "+RouteWipeProfile,
		handleAdmin(s, RouteWipeProfile, s.wipeProfile),
	)
	mux.HandleFunc(
		"POST "+RouteWipeSignLog,
		handleAdmin(s, RouteWipeSignLog, s.wipeSignLog),
	)
	mux.HandleFunc(
		"POST "+RouteWipeCold,
		handleAdmin(s, RouteWipeCold, s.wipeCold),
	)

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
	ids = append(ids, coldKeyIDs()...)
	ids = append(ids, hostKeysID)

	for slot := uint8(0); slot <= profile.MaxSlot; slot++ {
		ids = append(ids, profile.Profile{Slot: slot}.OwnerKeyID())
	}

	add(feeKeyFirst, feeKeyLast)

	for slot := uint8(0); slot <= profile.MaxSlot; slot++ {
		ids = append(
			ids,
			profile.Profile{Slot: slot}.PinsID(),
			profile.Profile{Slot: slot}.RecordID(),
		)
	}

	// the ownership record goes after the cold keys it describes; the signing
	// log head is chained to the identity key, so it goes with it
	return append(ids, ownersID, profile.SignLogHeadID, profile.IdentityKeyID)
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
			return nil, fmt.Errorf(
				"%w: deleting %#08x; send the request again",
				errDevice,
				id,
			)
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

	s.profiles, s.badSlots = map[string]profile.Profile{}, nil
	s.hostKeys, s.hostEntries, s.hostKeysBad = nil, nil, false
	s.logf("wipe: device wiped, %d objects deleted", len(deleted))

	return WipeResponse{Deleted: hexIDs(deleted)}, nil
}

// wipeSignLog deletes only the signing log head, so the signing firmware
// starts a new log on a zeroed card under the same identity key. Every entry
// on the old card stays verifiable with signlog-verify -image.
func (s *Service) wipeSignLog(req WipeSignLogRequest) (WipeResponse, error) {
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

	// an image removes only the profiles of the network and chain it serves
	p, err := s.profileFor(req.Profile)
	if err != nil {
		return WipeResponse{}, err
	}

	// an unreadable, misplaced or duplicate record may name the same cold
	// key or this profile's objects, so ownership cannot be established
	if len(s.badSlots) > 0 {
		return WipeResponse{}, errors.New(
			"a profile record is unreadable or inconsistent; wipe the device instead",
		)
	}

	// a stored record may name any object; delete only an armory cold key
	if !isColdKeyID(p.ColdKeyID) {
		return WipeResponse{}, errors.New(
			"profile cold key id outside the cold key range; wipe the device instead",
		)
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

	deleted, err := s.remove(append(ids, p.PinsID(), p.RecordID()))
	if err != nil {
		return WipeResponse{}, err
	}

	// the claim on a deleted cold key is dropped; a stale one frees the empty
	// object anyway, so a record that cannot be updated does not fail the wipe
	if !shared {
		if err = s.unclaim(p.ColdKeyID); err != nil {
			s.logf("wipe: claim on %#08x not cleared: %v", p.ColdKeyID, err)
		}
	}

	delete(s.profiles, p.Name)
	s.logf("wipe: profile %q slot %d removed", p.Name, p.Slot)

	return WipeResponse{Deleted: hexIDs(deleted)}, nil
}

// wipeCold deletes one cold key that no profile names, and its claim. It
// clears a key left with no owner, or one a scope no longer needs, without
// wiping the device. A key a profile names goes with /wipe/profile.
func (s *Service) wipeCold(req WipeColdRequest) (WipeResponse, error) {
	if err := s.confirm(req.IdentityPublicKey); err != nil {
		return WipeResponse{}, err
	}

	if !isColdKeyID(req.ColdKeyID) {
		return WipeResponse{}, errColdOwner
	}

	// an unreadable record may name this object
	if len(s.badSlots) > 0 {
		return WipeResponse{}, errors.New(
			"a profile record is unreadable or inconsistent; wipe the device instead",
		)
	}

	for _, p := range s.profiles {
		if p.ColdKeyID == req.ColdKeyID {
			return WipeResponse{}, errColdInUse
		}
	}

	key, err := s.objectKey(req.ColdKeyID)
	if err != nil {
		return WipeResponse{}, err
	}

	if key != nil {
		if err = s.mayWipeCold(req.ColdKeyID, s.callerOrImageScope()); err != nil {
			return WipeResponse{}, err
		}
	}

	deleted, err := s.remove([]uint32{req.ColdKeyID})
	if err != nil {
		return WipeResponse{}, err
	}

	// a stale claim frees the empty object anyway
	if err = s.unclaim(req.ColdKeyID); err != nil {
		s.logf("wipe: claim on %#08x not cleared: %v", req.ColdKeyID, err)
	}

	s.logf("wipe: cold key %#08x removed", req.ColdKeyID)

	return WipeResponse{Deleted: hexIDs(deleted)}, nil
}

func hexIDs(ids []uint32) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = fmt.Sprintf("%#08x", id)
	}

	return out
}
