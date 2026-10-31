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

// Package chipstore adapts the secure element to the signing log: the head
// store is a binary object and the identity is the device identity key.
//
// Both take the subsets of the firmware's chip the service already uses, so
// they run against the fake chips of the host tests.
//
// Atomicity assumption. The head object has a fixed size, so Store never
// deletes and recreates it once it exists, and the 76-byte record fits one
// short APDU (the se050 package writes up to 224 bytes in one). The first
// Store creates the object and writes it in that same APDU. The code relies
// on the secure element applying one write APDU to its persistent memory
// all-or-nothing, as the profile records and host key list already do; it
// was not verified against the applet. The record carries a checksum and
// Store reads the object back, so a torn or lost write shows as an error
// and not as a valid but wrong head.
package chipstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/armory/signlog"
)

const (
	headMagic = "BSLH"
	headLen   = len(headMagic) + 8 + signlog.HashSize + sha256.Size
)

// ErrHeadObject is returned when the head object exists but is not a valid
// head record. It is never read as an uninitialised head, which would let a
// blank card be formatted over a log.
var ErrHeadObject = errors.New("chipstore: head object is invalid")

// Objects is the binary object subset of the chip.
type Objects interface {
	Exists(id uint32) (bool, error)
	ReadBinary(id uint32) ([]byte, error)
	WriteBinary(id uint32, data []byte) error
}

// HeadStore keeps the signing log head in one binary object.
type HeadStore struct {
	objs Objects
	id   uint32
}

// NewHeadStore returns a head store in object id.
func NewHeadStore(objs Objects, id uint32) *HeadStore {
	return &HeadStore{objs: objs, id: id}
}

func encodeHead(h signlog.Head) []byte {
	b := make([]byte, 0, headLen)
	b = append(b, headMagic...)
	b = binary.BigEndian.AppendUint64(b, h.Seq)
	b = append(b, h.Hash[:]...)
	sum := sha256.Sum256(b)

	return append(b, sum[:]...)
}

func decodeHead(b []byte) (h signlog.Head, err error) {
	if len(b) != headLen || string(b[:len(headMagic)]) != headMagic {
		return h, fmt.Errorf("%w: %d bytes", ErrHeadObject, len(b))
	}

	sum := sha256.Sum256(b[:headLen-sha256.Size])
	if !bytes.Equal(sum[:], b[headLen-sha256.Size:]) {
		return h, fmt.Errorf("%w: checksum", ErrHeadObject)
	}

	h.Seq = binary.BigEndian.Uint64(b[len(headMagic):])
	copy(h.Hash[:], b[len(headMagic)+8:])

	return h, nil
}

// Load implements signlog.HeadStore. A missing object is the zero Head, the
// uninitialised store; an unreadable or invalid one is an error.
func (s *HeadStore) Load() (signlog.Head, error) {
	ok, err := s.objs.Exists(s.id)
	if err != nil {
		return signlog.Head{}, fmt.Errorf("chipstore: head object %#08x: %w", s.id, err)
	}

	if !ok {
		return signlog.Head{}, nil
	}

	b, err := s.objs.ReadBinary(s.id)
	if err != nil {
		return signlog.Head{}, fmt.Errorf("chipstore: read head object %#08x: %w", s.id, err)
	}

	return decodeHead(b)
}

// Store implements signlog.HeadStore. It writes the record and reads it back.
func (s *HeadStore) Store(h signlog.Head) error {
	b := encodeHead(h)

	if err := s.objs.WriteBinary(s.id, b); err != nil {
		return fmt.Errorf("chipstore: write head object %#08x: %w", s.id, err)
	}

	got, err := s.objs.ReadBinary(s.id)
	if err != nil {
		return fmt.Errorf("chipstore: read back head object %#08x: %w", s.id, err)
	}

	if !bytes.Equal(got, b) {
		return fmt.Errorf("%w: read back differs from what was written", ErrHeadObject)
	}

	return nil
}

// Keys is the key subset of the chip.
type Keys interface {
	Exists(id uint32) (bool, error)
	PublicKeyEd25519(id uint32) (ed25519.PublicKey, error)
	SignEd25519(id uint32, msg []byte) ([]byte, error)
}

// ErrNoIdentity is returned when the identity key object does not exist.
var ErrNoIdentity = errors.New("chipstore: identity key is not provisioned")

// Identity is the device identity key in the chip. The chip signs the
// message as given (pure Ed25519, as for inventory attestations), so the
// signatures verify with crypto/ed25519 under Public.
type Identity struct {
	keys Keys
	id   uint32
	pub  ed25519.PublicKey
}

// NewIdentity reads the public key of object id and checks that the chip's
// signature verifies under it.
func NewIdentity(keys Keys, id uint32) (*Identity, error) {
	ok, err := keys.Exists(id)
	if err != nil {
		return nil, fmt.Errorf("chipstore: identity key %#08x: %w", id, err)
	}

	if !ok {
		return nil, ErrNoIdentity
	}

	pub, err := keys.PublicKeyEd25519(id)
	if err != nil {
		return nil, fmt.Errorf("chipstore: read identity key %#08x: %w", id, err)
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("chipstore: identity key is %d bytes", len(pub))
	}

	i := &Identity{keys: keys, id: id, pub: pub}

	// the chip's output is checked on every Sign, so a first signature
	// confirms the key and the primitive before the log depends on them
	if _, err = i.Sign(selfTest[:]); err != nil {
		return nil, err
	}

	return i, nil
}

// Public implements signlog.Identity.
func (i *Identity) Public() ed25519.PublicKey { return i.pub }

// Sign implements signlog.Identity. The signature is verified under the
// public key before it is returned.
func (i *Identity) Sign(msg []byte) ([]byte, error) {
	sig, err := i.keys.SignEd25519(i.id, msg)
	if err != nil {
		return nil, fmt.Errorf("chipstore: sign: %w", err)
	}

	if !ed25519.Verify(i.pub, msg, sig) {
		return nil, errors.New("chipstore: identity signature does not verify under the identity key")
	}

	return sig, nil
}

// selfTest is the digest NewIdentity signs once.
var selfTest = sha256.Sum256([]byte("bursa-armory-signlog-identity-selftest/1"))
