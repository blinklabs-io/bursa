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

package sdmedium

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/armory/signlog"
)

// fakeCard is a usdhc-like card: whole-block transfers, writes that leave the
// card busy for a number of reads, and failure injection.
type fakeCard struct {
	img       []byte
	blockSize int
	detects   int

	detectErr error
	// busyReads is how many reads fail after a write, as while programming
	busyReads int
	busy      int
	// dropWrites accepts writes and stores nothing
	dropWrites bool
	// failWrites fails this many writes before succeeding
	failWrites int
	// failReads fails every read
	failReads bool
	reads     int
	writes    int
}

func newFakeCard(blocks int) *fakeCard {
	return &fakeCard{img: make([]byte, blocks*signlog.BlockSize), blockSize: signlog.BlockSize}
}

func (c *fakeCard) Detect() error {
	c.detects++

	return c.detectErr
}

func (c *fakeCard) Geometry() (int, uint64) {
	return c.blockSize, uint64(len(c.img) / signlog.BlockSize)
}

func (c *fakeCard) ReadBlocks(lba int, buf []byte) error {
	c.reads++

	if c.failReads {
		return errors.New("read failed")
	}

	if c.busy > 0 {
		c.busy--

		return errors.New("card busy")
	}

	copy(buf, c.img[lba*signlog.BlockSize:])

	return nil
}

func (c *fakeCard) WriteBlocks(lba int, buf []byte) error {
	c.writes++

	if c.failWrites > 0 {
		c.failWrites--

		return errors.New("write failed")
	}

	c.busy = c.busyReads

	if !c.dropWrites {
		copy(c.img[lba*signlog.BlockSize:], buf)
	}

	return nil
}

func open(t *testing.T, c *fakeCard) *Medium {
	t.Helper()

	m, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}

	m.sleep = func(time.Duration) {}

	return m
}

func TestOpenNilCard(t *testing.T) {
	t.Parallel()

	// a board without an SD slot hands over no card
	if _, err := Open(nil); !errors.Is(err, ErrNoCard) {
		t.Fatalf("got %v, want ErrNoCard", err)
	}
}

func TestOpenRefusals(t *testing.T) {
	t.Parallel()

	c := newFakeCard(16)
	c.detectErr = errors.New("no card detected on uSDHC1")

	if _, err := Open(c); !errors.Is(err, ErrNoCard) {
		t.Errorf("detect failure: %v, want ErrNoCard", err)
	}

	c = newFakeCard(16)
	c.blockSize = 4096

	if _, err := Open(c); err == nil {
		t.Error("4096-byte blocks accepted")
	}

	if _, err := Open(newFakeCard(0)); err == nil {
		t.Error("empty card accepted")
	}
}

func TestReadWriteAndBounds(t *testing.T) {
	t.Parallel()

	m := open(t, newFakeCard(16))
	data := bytes.Repeat([]byte{0xa5}, 2*signlog.BlockSize)

	if err := m.WriteBlocks(3, data); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(data))
	if err := m.ReadBlocks(3, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back: %v", err)
	}

	if m.NumBlocks() != 16 {
		t.Fatalf("NumBlocks %d", m.NumBlocks())
	}

	for name, fn := range map[string]func() error{
		"write past the end": func() error { return m.WriteBlocks(15, data) },
		"read past the end":  func() error { return m.ReadBlocks(16, make([]byte, signlog.BlockSize)) },
		"partial block":      func() error { return m.WriteBlocks(0, make([]byte, 100)) },
	} {
		if err := fn(); !errors.Is(err, signlog.ErrMedium) {
			t.Errorf("%s: %v, want ErrMedium", name, err)
		}
	}
}

func TestSyncWaitsForProgramming(t *testing.T) {
	t.Parallel()

	c := newFakeCard(16)
	c.busyReads = 5
	m := open(t, c)

	if err := m.WriteBlocks(1, bytes.Repeat([]byte{1}, signlog.BlockSize)); err != nil {
		t.Fatal(err)
	}

	if err := m.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// five busy reads, then the one that returned the data
	if c.reads != 6 {
		t.Fatalf("sync read %d times, want 6", c.reads)
	}
}

func TestSyncFailsWhenCardNeverReady(t *testing.T) {
	t.Parallel()

	c := newFakeCard(16)
	m := open(t, c)

	if err := m.WriteBlocks(1, make([]byte, signlog.BlockSize)); err != nil {
		t.Fatal(err)
	}

	c.failReads = true

	if err := m.Sync(); err == nil {
		t.Fatal("sync succeeded on a card that cannot be read")
	}
}

func TestSyncDetectsDroppedWrite(t *testing.T) {
	t.Parallel()

	c := newFakeCard(16)
	c.dropWrites = true
	m := open(t, c)

	if err := m.WriteBlocks(1, bytes.Repeat([]byte{1}, signlog.BlockSize)); err != nil {
		t.Fatal(err)
	}

	if err := m.Sync(); !errors.Is(err, ErrVerify) {
		t.Fatalf("got %v, want ErrVerify", err)
	}
}

func TestTransientIOErrorRedetectsOnce(t *testing.T) {
	t.Parallel()

	c := newFakeCard(16)
	c.failWrites = 1
	m := open(t, c)
	before := c.detects

	if err := m.WriteBlocks(1, make([]byte, signlog.BlockSize)); err != nil {
		t.Fatalf("write after a transient error: %v", err)
	}

	if c.detects != before+1 {
		t.Fatalf("detect called %d times", c.detects-before)
	}

	c.failWrites = 2

	if err := m.WriteBlocks(1, make([]byte, signlog.BlockSize)); err == nil {
		t.Fatal("a persistent write failure was not reported")
	}
}

func TestRemovedCardIsReported(t *testing.T) {
	t.Parallel()

	c := newFakeCard(16)
	m := open(t, c)
	c.failWrites = 2
	c.detectErr = errors.New("no card detected")

	if err := m.WriteBlocks(1, make([]byte, signlog.BlockSize)); err == nil {
		t.Fatal("write to a removed card succeeded")
	}
}

func newIdentity(t *testing.T) *signlog.KeySigner {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return signlog.NewKeySigner(priv)
}

func record() signlog.Record {
	return signlog.Record{
		Profile: "otg@preview", Role: "stake", Purpose: signlog.PurposeTxBody,
		BodyHash: bytes.Repeat([]byte{7}, 32), Summary: "fee=170000",
	}
}

// The log written through the adapter verifies from the raw card image.
func TestSignlogOverSDMedium(t *testing.T) {
	t.Parallel()

	c := newFakeCard(1 + 8*signlog.RecordBlocks)
	c.busyReads = 2
	m := open(t, c)
	id := newIdentity(t)
	heads := signlog.NewMemHeadStore(signlog.Head{})

	w, err := signlog.Open(m, heads, id)
	if err != nil {
		t.Fatal(err)
	}

	for range 3 {
		if _, err = w.Append(record()); err != nil {
			t.Fatal(err)
		}
	}

	log, err := signlog.Verify(signlog.NewReaderMedium(bytes.NewReader(c.img), int64(len(c.img))), id.Public())
	if err != nil || len(log.Entries) != 3 {
		t.Fatalf("verify: %v", err)
	}

	// a reopened writer accepts the card
	if _, err = signlog.Open(open(t, c), heads, id); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

// A card that drops a write makes Append fail and leaves the head alone, so
// no signature is released for an entry that is not on the card.
func TestDroppedWriteRefusesAppend(t *testing.T) {
	t.Parallel()

	c := newFakeCard(1 + 8*signlog.RecordBlocks)
	m := open(t, c)
	id := newIdentity(t)
	heads := signlog.NewMemHeadStore(signlog.Head{})

	w, err := signlog.Open(m, heads, id)
	if err != nil {
		t.Fatal(err)
	}

	before := w.Head()
	c.dropWrites = true

	if _, err = w.Append(record()); err == nil {
		t.Fatal("append succeeded on a card that dropped the write")
	}

	if stored, _ := heads.Load(); stored != before {
		t.Fatalf("head moved to %+v", stored)
	}
}

// A failed Sync does not leave its writes pending: once the card recovers,
// the slot rewritten with other data syncs.
func TestSyncRecoversAfterFailure(t *testing.T) {
	t.Parallel()

	c := newFakeCard(16)
	m := open(t, c)

	if err := m.WriteBlocks(1, bytes.Repeat([]byte{1}, signlog.BlockSize)); err != nil {
		t.Fatal(err)
	}

	c.failReads = true

	if err := m.Sync(); err == nil {
		t.Fatal("sync succeeded on a card that cannot be read")
	}

	c.failReads = false

	if err := m.WriteBlocks(1, bytes.Repeat([]byte{2}, signlog.BlockSize)); err != nil {
		t.Fatal(err)
	}

	if err := m.Sync(); err != nil {
		t.Fatalf("sync after the card recovered: %v", err)
	}
}

// After a failed Sync the writer can append again once the card recovers.
func TestAppendRecoversAfterFailedSync(t *testing.T) {
	t.Parallel()

	c := newFakeCard(1 + 8*signlog.RecordBlocks)
	m := open(t, c)
	id := newIdentity(t)
	heads := signlog.NewMemHeadStore(signlog.Head{})

	w, err := signlog.Open(m, heads, id)
	if err != nil {
		t.Fatal(err)
	}

	c.dropWrites = true

	if _, err = w.Append(record()); err == nil {
		t.Fatal("append succeeded on a card that dropped the write")
	}

	c.dropWrites = false
	rec := record()
	rec.BodyHash = bytes.Repeat([]byte{8}, 32)

	if _, err = w.Append(rec); err != nil {
		t.Fatalf("append after the card recovered: %v", err)
	}
}
