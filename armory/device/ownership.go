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
	"errors"
)

// Cold key objects: the block older images used and a second one, 32 in all.
const (
	coldKeyFirst uint32 = 0x20e50010
	coldKeyLast  uint32 = 0x20e5001f

	coldKeyMoreFirst uint32 = 0x20e50600
	coldKeyMoreLast  uint32 = 0x20e5060f

	coldKeyCount = int(coldKeyLast-coldKeyFirst) + int(coldKeyMoreLast-coldKeyMoreFirst) + 2
)

// ownersID holds the ownership record of the cold key objects: one binary
// object of ownersSize bytes, always written whole with a single WriteBinary.
// It is a version byte (ownersVersion) followed by one entry per cold key
// object in coldKeyIndex order. An entry is a claimed flag (0 none, 1
// claimed), the network id and the chain tag of the owning scope, as the host
// key list encodes them. A claim only says which scope imported the key; it
// never locks an empty object.
const (
	ownersID      uint32 = 0x20e50023
	ownersVersion byte   = 1
	ownerEntry           = 1 + 1 + chainTagSize
	ownersSize           = 1 + coldKeyCount*ownerEntry
)

var (
	// errColdOwner refuses a cold key object another scope owns, or one that
	// holds a key nobody owns
	errColdOwner = errors.New("cold key object belongs to another scope, or holds a key with no owner; wipe it")
	// errOwnersRecord is the ownership record that cannot be trusted
	errOwnersRecord = errors.New("cold key ownership record is corrupt; wipe the device")
)

// isColdKeyID reports whether id is a cold key object.
func isColdKeyID(id uint32) bool {
	_, ok := coldKeyIndex(id)
	return ok
}

// coldKeyIndex is the position of cold key object id in the ownership record.
func coldKeyIndex(id uint32) (int, bool) {
	switch {
	case id >= coldKeyFirst && id <= coldKeyLast:
		return int(id - coldKeyFirst), true
	case id >= coldKeyMoreFirst && id <= coldKeyMoreLast:
		return int(coldKeyLast-coldKeyFirst) + 1 + int(id-coldKeyMoreFirst), true
	}

	return 0, false
}

// coldKeyIDs lists every cold key object in record order.
func coldKeyIDs() []uint32 {
	ids := make([]uint32, 0, coldKeyCount)

	for id := coldKeyFirst; id <= coldKeyLast; id++ {
		ids = append(ids, id)
	}

	for id := coldKeyMoreFirst; id <= coldKeyMoreLast; id++ {
		ids = append(ids, id)
	}

	return ids
}

// scopeTag is the stored form of a scope.
type scopeTag struct {
	network uint8
	chain   [chainTagSize]byte
}

func tagOf(sc Scope) scopeTag { return scopeTag{network: sc.Network, chain: chainTag(sc.Chain)} }

// owners is the ownership record: the claim of each cold key object.
type owners [coldKeyCount]struct {
	claimed bool
	tag     scopeTag
}

// readOwners returns the ownership record; a chip without one has no claims.
// A record that cannot be read or is malformed is an error, so a check that
// needs it fails closed.
func (s *Service) readOwners() (owners, error) {
	var o owners

	ok, err := s.chip.Exists(ownersID)
	if err != nil {
		s.logf("exist check %#08x: %v", ownersID, err)
		return o, errDevice
	}

	if !ok {
		return o, nil
	}

	b, err := s.chip.ReadBinary(ownersID)
	if err != nil {
		s.logf("read %#08x: %v", ownersID, err)
		return o, errDevice
	}

	if len(b) != ownersSize || b[0] != ownersVersion {
		s.logf("ownership record: %d bytes, version %d", len(b), versionOf(b))
		return o, errOwnersRecord
	}

	for i := range o {
		e := b[1+i*ownerEntry:]

		switch e[0] {
		case 0:
		case 1:
			o[i].claimed, o[i].tag.network = true, e[1]
			copy(o[i].tag.chain[:], e[2:ownerEntry])
		default:
			s.logf("ownership record: entry %d flag %d", i, e[0])
			return o, errOwnersRecord
		}
	}

	return o, nil
}

func versionOf(b []byte) int {
	if len(b) == 0 {
		return -1
	}

	return int(b[0])
}

// writeOwners stores the record whole and reads it back.
func (s *Service) writeOwners(o owners) error {
	b := make([]byte, ownersSize)
	b[0] = ownersVersion

	for i, e := range o {
		if !e.claimed {
			continue
		}

		slot := b[1+i*ownerEntry:]
		slot[0], slot[1] = 1, e.tag.network
		copy(slot[2:], e.tag.chain[:])
	}

	if err := s.chip.WriteBinary(ownersID, b); err != nil {
		s.logf("write %#08x: %v", ownersID, err)
		return errDevice
	}

	got, err := s.chip.ReadBinary(ownersID)
	if err != nil || !bytes.Equal(got, b) {
		s.logf("write %#08x: read back: %v", ownersID, err)
		return errDevice
	}

	return nil
}

// claim records sc as the owner of cold key object id.
func (s *Service) claim(id uint32, sc Scope) error {
	i, ok := coldKeyIndex(id)
	if !ok {
		return errColdOwner
	}

	o, err := s.readOwners()
	if err != nil {
		return err
	}

	if o[i].claimed && o[i].tag == tagOf(sc) {
		return nil
	}

	o[i].claimed, o[i].tag = true, tagOf(sc)

	return s.writeOwners(o)
}

// unclaim drops the claim on cold key object id, if the record has one.
func (s *Service) unclaim(id uint32) error {
	i, ok := coldKeyIndex(id)
	if !ok {
		return nil
	}

	o, err := s.readOwners()
	if err != nil {
		return err
	}

	if !o[i].claimed {
		return nil
	}

	o[i].claimed = false
	o[i].tag = scopeTag{}

	return s.writeOwners(o)
}

// profileTag is the scope a stored profile is for, whether or not this image
// serves it: network 0 is testnet, a mainnet profile's scope is the label its
// name ends with.
func profileTag(network uint8, name string) scopeTag {
	if network == 0 {
		return tagOf(ScopeTestnet)
	}

	chain := ""

	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '@' {
			chain = name[i+1:]
			break
		}
	}

	return tagOf(Scope{Network: network, Chain: chain})
}

// coldOwner returns the owner of cold key object id, which holds a key: the
// claim in the record, else the scope of a profile whose cold key it is, else
// none (ok false).
func (s *Service) coldOwner(id uint32) (tag scopeTag, ok bool, err error) {
	i, isCold := coldKeyIndex(id)
	if !isCold {
		return tag, false, errColdOwner
	}

	o, err := s.readOwners()
	if err != nil {
		return tag, false, err
	}

	if o[i].claimed {
		return o[i].tag, true, nil
	}

	for _, p := range s.profiles {
		if p.ColdKeyID == id {
			return profileTag(p.NetworkID, p.Name), true, nil
		}
	}

	return tag, false, nil
}

// requireOwner refuses cold key object id, which holds a key, unless sc owns
// it. An object with a key and no owner is refused to every scope.
func (s *Service) requireOwner(id uint32, sc Scope) error {
	tag, ok, err := s.coldOwner(id)
	if err != nil {
		return err
	}

	if !ok || tag != tagOf(sc) {
		return errColdOwner
	}

	return nil
}

// callerOrImageScope is the scope a cold key import or profile is made for.
func (s *Service) callerOrImageScope() Scope {
	if s.multi() {
		return s.caller.scope
	}

	return s.imageScope()
}

// refuseOtherOwner refuses cold key object id when it holds a key another
// scope owns. An unowned key passes.
func (s *Service) refuseOtherOwner(id uint32, sc Scope) error {
	key, err := s.objectKey(id)
	if err != nil || key == nil {
		return err
	}

	tag, ok, err := s.coldOwner(id)
	if err != nil {
		return err
	}

	if ok && tag != tagOf(sc) {
		return errColdOwner
	}

	return nil
}
