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

package chipstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/bursa/armory/signlog"
)

// fakeChip is a software SE050 object store and key store.
type fakeChip struct {
	bins map[uint32][]byte
	keys map[uint32]ed25519.PrivateKey

	failExists, failRead, failWrite bool
	// tornWrite stores half the record and reports success
	tornWrite bool
	// lostWrite reports success and stores nothing
	lostWrite bool
	// badSign returns a signature over another message
	badSign bool
}

func newFakeChip() *fakeChip {
	return &fakeChip{bins: map[uint32][]byte{}, keys: map[uint32]ed25519.PrivateKey{}}
}

func (c *fakeChip) Exists(id uint32) (bool, error) {
	if c.failExists {
		return false, errors.New("i2c failure")
	}

	_, b := c.bins[id]
	_, k := c.keys[id]

	return b || k, nil
}

func (c *fakeChip) ReadBinary(id uint32) ([]byte, error) {
	if c.failRead {
		return nil, errors.New("i2c failure")
	}

	b, ok := c.bins[id]
	if !ok {
		return nil, errors.New("no object")
	}

	return bytes.Clone(b), nil
}

func (c *fakeChip) WriteBinary(id uint32, data []byte) error {
	if c.failWrite {
		return errors.New("i2c failure")
	}

	switch {
	case c.lostWrite:
	case c.tornWrite:
		c.bins[id] = bytes.Clone(data[:len(data)/2])
	default:
		c.bins[id] = bytes.Clone(data)
	}

	return nil
}

func (c *fakeChip) PublicKeyEd25519(id uint32) (ed25519.PublicKey, error) {
	k, ok := c.keys[id]
	if !ok {
		return nil, errors.New("no key")
	}

	return k.Public().(ed25519.PublicKey), nil
}

func (c *fakeChip) SignEd25519(id uint32, msg []byte) ([]byte, error) {
	k, ok := c.keys[id]
	if !ok {
		return nil, errors.New("no key")
	}

	if c.badSign {
		msg = append([]byte("x"), msg...)
	}

	return ed25519.Sign(k, msg), nil
}

func TestHeadStoreRoundTrip(t *testing.T) {
	t.Parallel()

	c := newFakeChip()
	s := NewHeadStore(c, profile.SignLogHeadID)

	if h, err := s.Load(); err != nil || h != (signlog.Head{}) {
		t.Fatalf("missing object: %+v, %v; want the zero head", h, err)
	}

	want := signlog.Head{Seq: 41, Hash: sha256.Sum256([]byte("entry 41"))}
	if err := s.Store(want); err != nil {
		t.Fatal(err)
	}

	if got, err := s.Load(); err != nil || got != want {
		t.Fatalf("got %+v, %v; want %+v", got, err, want)
	}

	// the record is written to the object ID the firmware reserves for it
	if len(c.bins[profile.SignLogHeadID]) != headLen {
		t.Fatalf("object holds %d bytes, want %d", len(c.bins[profile.SignLogHeadID]), headLen)
	}

	// a second store replaces it in place
	next := signlog.Head{Seq: 42, Hash: sha256.Sum256([]byte("entry 42"))}
	if err := s.Store(next); err != nil {
		t.Fatal(err)
	}

	if got, _ := s.Load(); got != next {
		t.Fatalf("got %+v, want %+v", got, next)
	}
}

// An object that exists but does not decode is an error and never the zero
// head, which would let a blank card be formatted over an existing log.
func TestHeadStoreInvalidObjectIsNotUninitialised(t *testing.T) {
	t.Parallel()

	good := encodeHead(signlog.Head{Seq: 3, Hash: sha256.Sum256([]byte("x"))})

	flip := func(i int) []byte {
		b := bytes.Clone(good)
		b[i] ^= 1

		return b
	}

	for name, obj := range map[string][]byte{
		"torn":         good[:len(good)/2],
		"empty":        {},
		"bad magic":    flip(0),
		"bad seq":      flip(5),
		"bad hash":     flip(14),
		"bad checksum": flip(len(good) - 1),
		"long":         append(bytes.Clone(good), 0),
	} {
		c := newFakeChip()
		c.bins[profile.SignLogHeadID] = obj

		h, err := NewHeadStore(c, profile.SignLogHeadID).Load()
		if !errors.Is(err, ErrHeadObject) || h != (signlog.Head{}) {
			t.Errorf("%s: %+v, %v; want ErrHeadObject", name, h, err)
		}
	}
}

func TestHeadStoreChipErrors(t *testing.T) {
	t.Parallel()

	h := signlog.Head{Seq: 1, Hash: sha256.Sum256([]byte("e"))}

	c := newFakeChip()
	c.failExists = true

	if _, err := NewHeadStore(c, profile.SignLogHeadID).Load(); err == nil {
		t.Error("exists failure read as an uninitialised head")
	}

	c = newFakeChip()
	c.bins[profile.SignLogHeadID] = encodeHead(h)
	c.failRead = true

	if _, err := NewHeadStore(c, profile.SignLogHeadID).Load(); err == nil {
		t.Error("read failure read as a head")
	}

	for name, mut := range map[string]func(*fakeChip){
		"write fails": func(c *fakeChip) { c.failWrite = true },
		"torn write":  func(c *fakeChip) { c.tornWrite = true },
		"lost write":  func(c *fakeChip) { c.lostWrite = true },
	} {
		c = newFakeChip()
		c.bins[profile.SignLogHeadID] = encodeHead(signlog.Head{})
		mut(c)

		if err := NewHeadStore(c, profile.SignLogHeadID).Store(h); err == nil {
			t.Errorf("%s: Store reported success", name)
		}
	}
}

func provisioned(t *testing.T) (*fakeChip, ed25519.PublicKey) {
	t.Helper()

	c := newFakeChip()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	c.keys[profile.IdentityKeyID] = priv

	return c, priv.Public().(ed25519.PublicKey)
}

func TestIdentitySignsWhatSignlogExpects(t *testing.T) {
	t.Parallel()

	c, pub := provisioned(t)

	id, err := NewIdentity(c, profile.IdentityKeyID)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(id.Public(), pub) {
		t.Fatal("public key differs from the chip's")
	}

	// the same path signlog uses: pure Ed25519 over the 32-byte digest
	digest := sha256.Sum256([]byte("digest"))

	sig, err := id.Sign(digest[:])
	if err != nil || !ed25519.Verify(pub, digest[:], sig) {
		t.Fatalf("signature does not verify with crypto/ed25519: %v", err)
	}
}

// A log written through the adapters verifies host-side with the identity
// public key and carries the head the chip stores.
func TestLogThroughAdapters(t *testing.T) {
	t.Parallel()

	c, pub := provisioned(t)

	id, err := NewIdentity(c, profile.IdentityKeyID)
	if err != nil {
		t.Fatal(err)
	}

	heads := NewHeadStore(c, profile.SignLogHeadID)
	m := signlog.NewMemMedium(1 + 4*signlog.RecordBlocks)

	w, err := signlog.Open(m, heads, id)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 3 {
		if _, err = w.Append(signlog.Record{
			Profile: "otg@preview", Role: "pool", Purpose: signlog.PurposeTxBody,
			BodyHash: bytes.Repeat([]byte{byte(i + 1)}, 32), Summary: "fee=1",
		}); err != nil {
			t.Fatal(err)
		}
	}

	log, err := signlog.Verify(m, pub)
	if err != nil || len(log.Entries) != 3 {
		t.Fatalf("verify: %v", err)
	}

	if stored, err := heads.Load(); err != nil || stored != log.Head() || stored != w.Head() {
		t.Fatalf("stored head %+v, %v; log head %+v", stored, err, log.Head())
	}

	// a wiped head object with the card's entries still on it is refused
	delete(c.bins, profile.SignLogHeadID)

	if _, err = signlog.Open(m, heads, id); !errors.Is(err, signlog.ErrAhead) {
		t.Fatalf("reopen with the head object gone: %v, want ErrAhead", err)
	}
}

func TestIdentityRefusals(t *testing.T) {
	t.Parallel()

	if _, err := NewIdentity(newFakeChip(), profile.IdentityKeyID); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("no key: %v, want ErrNoIdentity", err)
	}

	c := newFakeChip()
	c.failExists = true

	if _, err := NewIdentity(c, profile.IdentityKeyID); err == nil {
		t.Error("chip error accepted")
	}

	// a chip whose signatures do not verify under its own public key
	c, _ = provisioned(t)
	c.badSign = true

	if _, err := NewIdentity(c, profile.IdentityKeyID); err == nil {
		t.Error("non-verifying chip accepted")
	}

	c, _ = provisioned(t)

	id, err := NewIdentity(c, profile.IdentityKeyID)
	if err != nil {
		t.Fatal(err)
	}

	c.badSign = true

	if _, err = id.Sign(make([]byte, 32)); err == nil {
		t.Error("bad signature returned")
	}
}
