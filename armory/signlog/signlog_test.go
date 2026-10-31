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

package signlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

var (
	errInjected = errors.New("injected failure")
	// testBlocks holds the header and capacity slots.
	testBlocks = func(slots int) uint64 { return uint64(1 + slots*RecordBlocks) }
)

type fixture struct {
	pub    ed25519.PublicKey
	id     *KeySigner
	medium *MemMedium
	heads  *MemHeadStore
}

func newFixture(t *testing.T, slots int) *fixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return &fixture{
		pub:    pub,
		id:     NewKeySigner(priv),
		medium: NewMemMedium(testBlocks(slots)),
		heads:  NewMemHeadStore(Head{}),
	}
}

func (f *fixture) open(t *testing.T) *Writer {
	t.Helper()

	w, err := Open(f.medium, f.heads, f.id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	return w
}

func bodyRecord(n byte) Record {
	return Record{
		Profile:  "otg@preview",
		Role:     "stake",
		Purpose:  PurposeTxBody,
		BodyHash: bytes.Repeat([]byte{n}, 32),
		Summary:  "fee=170000 pool-reg pledge=1 cost=2 margin=1/10 relays=1 leios=false",
	}
}

func opcertRecord(issue uint64) Record {
	return Record{
		Profile:      "otg@preview",
		Role:         "pool",
		Purpose:      PurposeOpCertNext,
		IssueCounter: issue,
		KESPeriod:    700,
		KESKeyHash:   bytes.Repeat([]byte{0xab}, 32),
		Summary:      "chain 4 issue 5 period 700",
	}
}

// fill appends n alternating records and returns the entries.
func (f *fixture) fill(t *testing.T, w *Writer, n int) []Entry {
	t.Helper()

	var out []Entry

	for i := range n {
		rec := bodyRecord(byte(i + 1))
		if i%2 == 1 {
			rec = opcertRecord(uint64(i))
		}

		e, err := w.Append(rec)
		if err != nil {
			t.Fatalf("append %d: %v", i+1, err)
		}

		out = append(out, e)
	}

	return out
}

func (f *fixture) verify(t *testing.T, pub ed25519.PublicKey) (*Log, error) {
	t.Helper()

	return Verify(f.medium, pub)
}

func slotOffset(seq int) int { return (1 + (seq-1)*RecordBlocks) * BlockSize }

// mutate edits the medium image in place.
func (f *fixture) mutate(t *testing.T, fn func(img []byte)) {
	t.Helper()

	img := f.medium.Image()
	fn(img)

	if err := f.medium.WriteBlocks(0, img); err != nil {
		t.Fatal(err)
	}
}

// refix recomputes a record's checksum so only the signature can object.
func refix(img []byte, seq int) {
	rec := img[slotOffset(seq) : slotOffset(seq)+RecordSize]
	sum := sha256.Sum256(rec[:RecordSize-sha256.Size])
	copy(rec[RecordSize-sha256.Size:], sum[:])
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	w := f.open(t)
	want := f.fill(t, w, 5)

	log, err := f.verify(t, f.pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if len(log.Entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(log.Entries), len(want))
	}

	for i, e := range log.Entries {
		if e.Seq != uint64(i+1) {
			t.Errorf("entry %d has seq %d", i, e.Seq)
		}

		if e.Hash != want[i].Hash || !bytes.Equal(e.Signature, want[i].Signature) {
			t.Errorf("entry %d differs from the appended one", i)
		}

		if e.Record.Profile != want[i].Record.Profile || e.Purpose != want[i].Purpose ||
			!bytes.Equal(e.BodyHash, want[i].BodyHash) || e.Summary != want[i].Summary ||
			e.IssueCounter != want[i].IssueCounter || e.KESPeriod != want[i].KESPeriod ||
			!bytes.Equal(e.KESKeyHash, want[i].KESKeyHash) || e.Role != want[i].Role {
			t.Errorf("entry %d record differs: %+v vs %+v", i, e.Record, want[i].Record)
		}
	}

	if log.Entries[0].Prev != log.Header.Hash {
		t.Error("first entry does not chain from the header")
	}

	if !bytes.Equal(log.Header.Identity, f.pub) {
		t.Error("header identity is not the device key")
	}

	for i := 1; i < len(log.Entries); i++ {
		if log.Entries[i].Prev != log.Entries[i-1].Hash {
			t.Errorf("entry %d does not chain from entry %d", i+1, i)
		}
	}

	head, _ := f.heads.Load()
	if head.Seq != 5 || head.Hash != log.Entries[4].Hash || w.Head() != head {
		t.Errorf("head %+v does not name the last entry", head)
	}

	// everything past the last record is untouched
	img := f.medium.Image()
	if len(img)%BlockSize != 0 || !bytes.Equal(img[slotOffset(6):], make([]byte, len(img)-slotOffset(6))) {
		t.Error("image is not block aligned or wrote past the last entry")
	}
}

func TestReopenContinues(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	f.fill(t, f.open(t), 3)

	w := f.open(t)
	if w.Head().Seq != 3 {
		t.Fatalf("reopened head seq %d, want 3", w.Head().Seq)
	}

	e, err := w.Append(bodyRecord(9))
	if err != nil || e.Seq != 4 {
		t.Fatalf("append after reopen: seq %d err %v", e.Seq, err)
	}

	if log, err := f.verify(t, f.pub); err != nil || len(log.Entries) != 4 {
		t.Fatalf("verify: %v", err)
	}
}

func TestEmptyLogVerifies(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 4)
	f.open(t)

	log, err := f.verify(t, f.pub)
	if err != nil || len(log.Entries) != 0 {
		t.Fatalf("empty log: %v", err)
	}

	head, _ := f.heads.Load()
	if head.Seq != 0 || head.Hash != log.Header.Hash || head.Hash == ([HashSize]byte{}) {
		t.Errorf("head %+v is not the header hash", head)
	}
}

func TestHeaderOnlyMediumWithBlankHeadIsAdopted(t *testing.T) {
	t.Parallel()

	// crash between formatting the card and storing the first head
	f := newFixture(t, 4)
	f.open(t)
	f.heads.Store(Head{})

	w := f.open(t)
	if _, err := w.Append(bodyRecord(1)); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func TestBlankHeadWithEntriesRefused(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 4)
	f.fill(t, f.open(t), 2)
	f.heads.Store(Head{})

	if _, err := Open(f.medium, f.heads, f.id); !errors.Is(err, ErrAhead) {
		t.Fatalf("got %v, want ErrAhead", err)
	}
}

func TestTamperDetected(t *testing.T) {
	t.Parallel()

	// offsets in the magic, the length, the payload, the signature and the
	// checksum of the record
	for _, off := range []int{0, 4, 6, 40, 200, RecordSize - 96, RecordSize - 40, RecordSize - 1} {
		for seq := 1; seq <= 4; seq++ {
			f := newFixture(t, 8)
			f.fill(t, f.open(t), 4)
			f.mutate(t, func(img []byte) { img[slotOffset(seq)+off] ^= 0x01 })

			_, err := f.verify(t, f.pub)
			if err == nil {
				t.Errorf("flip at entry %d offset %d went unnoticed", seq, off)
			}
		}
	}
}

func TestTamperWithFixedChecksumFailsSignature(t *testing.T) {
	t.Parallel()

	for _, off := range []int{8, 40, 100, 200} {
		f := newFixture(t, 8)
		f.fill(t, f.open(t), 4)
		f.mutate(t, func(img []byte) {
			img[slotOffset(2)+off] ^= 0x01
			refix(img, 2)
		})

		if _, err := f.verify(t, f.pub); !errors.Is(err, ErrBadSignature) &&
			!errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrChain) {
			t.Errorf("offset %d: got %v, want ErrBadSignature, ErrCorrupt or ErrChain", off, err)
		}
	}
}

func TestTamperedSignatureWithFixedChecksum(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	f.fill(t, f.open(t), 4)
	f.mutate(t, func(img []byte) {
		img[slotOffset(2)+RecordSize-96] ^= 0x01
		refix(img, 2)
	})

	if _, err := f.verify(t, f.pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestDropEntryDetected(t *testing.T) {
	t.Parallel()

	// close the gap by shifting later entries down
	f := newFixture(t, 8)
	f.fill(t, f.open(t), 4)
	f.mutate(t, func(img []byte) {
		copy(img[slotOffset(2):], img[slotOffset(3):slotOffset(5)])
		clear(img[slotOffset(4):slotOffset(5)])
	})

	if _, err := f.verify(t, f.pub); !errors.Is(err, ErrSequence) {
		t.Fatalf("shifted: got %v, want ErrSequence", err)
	}

	// blank the slot and leave the later entries in place
	f = newFixture(t, 8)
	f.fill(t, f.open(t), 4)
	f.mutate(t, func(img []byte) { clear(img[slotOffset(2):slotOffset(3)]) })

	if _, err := f.verify(t, f.pub); !errors.Is(err, ErrTrailing) {
		t.Fatalf("blanked: got %v, want ErrTrailing", err)
	}
}

func TestReorderDetected(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	f.fill(t, f.open(t), 4)
	f.mutate(t, func(img []byte) {
		a := bytes.Clone(img[slotOffset(2) : slotOffset(2)+RecordSize])
		copy(img[slotOffset(2):], img[slotOffset(3):slotOffset(3)+RecordSize])
		copy(img[slotOffset(3):], a)
	})

	if _, err := f.verify(t, f.pub); !errors.Is(err, ErrSequence) {
		t.Fatalf("got %v, want ErrSequence", err)
	}
}

func TestForgedEntryDetected(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	f.fill(t, f.open(t), 4)

	// a well-formed entry 3 from another key on a card with the same
	// header, framed and chained correctly
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	log, err := f.verify(t, f.pub)
	if err != nil {
		t.Fatal(err)
	}

	forged := bodyRecord(0x66)
	e := Entry{Record: forged, Seq: 3, Prev: log.Entries[1].Hash}

	rec, err := frameEntry(e, NewKeySigner(attacker))
	if err != nil {
		t.Fatal(err)
	}

	f.mutate(t, func(img []byte) { copy(img[slotOffset(3):], rec) })

	if _, err := f.verify(t, f.pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestSplicedGenuineEntryBreaksChain(t *testing.T) {
	t.Parallel()

	// entry 3 of a second card of the same device is validly signed and
	// correctly numbered, but chains from that card's own history
	f := newFixture(t, 8)
	f.fill(t, f.open(t), 4)

	g := &fixture{pub: f.pub, id: f.id, medium: NewMemMedium(testBlocks(8)), heads: NewMemHeadStore(Head{})}
	g.fill(t, g.open(t), 3)

	other := g.medium.Image()
	f.mutate(t, func(img []byte) {
		copy(img[slotOffset(3):], other[slotOffset(3):slotOffset(3)+RecordSize])
	})

	if _, err := f.verify(t, f.pub); !errors.Is(err, ErrChain) {
		t.Fatalf("got %v, want ErrChain", err)
	}

	// the same splice at the head of the log
	f = newFixture(t, 8)
	f.fill(t, f.open(t), 2)
	f.mutate(t, func(img []byte) {
		copy(img[slotOffset(1):], other[slotOffset(1):slotOffset(1)+RecordSize])
	})

	if _, err := f.verify(t, f.pub); !errors.Is(err, ErrChain) {
		t.Fatalf("first entry: got %v, want ErrChain", err)
	}
}

func TestInsertedForgedEntryDetected(t *testing.T) {
	t.Parallel()

	// a forged entry inserted between 2 and 3, shifting the rest up
	f := newFixture(t, 8)
	f.fill(t, f.open(t), 4)

	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	log, _ := f.verify(t, f.pub)
	e := Entry{Record: bodyRecord(0x77), Seq: 3, Prev: log.Entries[1].Hash}

	rec, err := frameEntry(e, NewKeySigner(attacker))
	if err != nil {
		t.Fatal(err)
	}

	f.mutate(t, func(img []byte) {
		copy(img[slotOffset(4):], img[slotOffset(3):slotOffset(5)])
		copy(img[slotOffset(3):], rec)
	})

	if _, err := f.verify(t, f.pub); err == nil {
		t.Fatal("inserted entry went unnoticed")
	}
}

func TestOlderCopyRefusedAtOpen(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	w := f.open(t)
	f.fill(t, w, 2)
	older := f.medium.Image()
	f.fill(t, w, 2)

	// the older card verifies on its own; only the head catches it
	if err := f.medium.WriteBlocks(0, older); err != nil {
		t.Fatal(err)
	}

	if _, err := f.verify(t, f.pub); err != nil {
		t.Fatalf("older copy should verify standalone: %v", err)
	}

	if _, err := Open(f.medium, f.heads, f.id); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want ErrRollback", err)
	}
}

func TestOlderCopySwappedUnderWriterRefusedAtAppend(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	w := f.open(t)
	f.fill(t, w, 2)
	older := f.medium.Image()
	f.fill(t, w, 1)

	if err := f.medium.WriteBlocks(0, older); err != nil {
		t.Fatal(err)
	}

	if _, err := w.Append(bodyRecord(5)); err == nil {
		t.Fatal("append succeeded on a swapped card")
	}

	if head, _ := f.heads.Load(); head.Seq != 3 {
		t.Errorf("head moved to %d", head.Seq)
	}
}

func TestBlankCardWithHeadRefused(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	f.fill(t, f.open(t), 2)

	blank := NewMemMedium(testBlocks(8))
	if _, err := Open(blank, f.heads, f.id); !errors.Is(err, ErrBlank) {
		t.Fatalf("got %v, want ErrBlank", err)
	}

	// a head with seq 0 that names a header is also not blank-compatible
	g := newFixture(t, 8)
	g.open(t)

	if _, err := Open(NewMemMedium(testBlocks(8)), g.heads, g.id); !errors.Is(err, ErrBlank) {
		t.Fatalf("seq 0 head: got %v, want ErrBlank", err)
	}
}

func TestTruncatedRecordRefusedAtOpen(t *testing.T) {
	t.Parallel()

	for name, cut := range map[string]func(img []byte){
		"second half zeroed": func(img []byte) { clear(img[slotOffset(3)+RecordSize/2 : slotOffset(3)+RecordSize]) },
		"first half zeroed":  func(img []byte) { clear(img[slotOffset(3) : slotOffset(3)+RecordSize/2]) },
		"slot blanked":       func(img []byte) { clear(img[slotOffset(3) : slotOffset(3)+RecordSize]) },
	} {
		f := newFixture(t, 8)
		f.fill(t, f.open(t), 3)
		f.mutate(t, cut)

		if _, err := Open(f.medium, f.heads, f.id); !errors.Is(err, ErrRollback) {
			t.Errorf("%s: got %v, want ErrRollback", name, err)
		}
	}
}

func TestMismatchedHashRefusedAtOpen(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	f.fill(t, f.open(t), 3)

	head, _ := f.heads.Load()
	head.Hash[0] ^= 1
	f.heads.Store(head)

	if _, err := Open(f.medium, f.heads, f.id); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("got %v, want ErrHashMismatch", err)
	}
}

func TestDifferentDeviceRefused(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	f.fill(t, f.open(t), 2)

	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	if _, err := Verify(f.medium, otherPub); !errors.Is(err, ErrWrongDevice) {
		t.Fatalf("verify: got %v, want ErrWrongDevice", err)
	}

	if _, err := Open(f.medium, f.heads, NewKeySigner(otherPriv)); !errors.Is(err, ErrWrongDevice) {
		t.Fatalf("open: got %v, want ErrWrongDevice", err)
	}
}

func TestForgedHeaderDetected(t *testing.T) {
	t.Parallel()

	// a card formatted by an attacker's key claiming the pinned identity
	f := newFixture(t, 4)
	f.open(t)
	f.mutate(t, func(img []byte) { img[100] ^= 1 })

	if _, err := f.verify(t, f.pub); err == nil {
		t.Fatal("header tamper went unnoticed")
	}
}

// faultMedium injects failures into a MemMedium.
type faultMedium struct {
	*MemMedium
	mu        sync.Mutex
	failWrite bool
	tornAfter int // blocks written before failing; -1 for none
	failSync  bool
	dirty     bool // written since the last successful Sync
}

func newFaultMedium(blocks uint64) *faultMedium {
	return &faultMedium{MemMedium: NewMemMedium(blocks), tornAfter: -1}
}

func (m *faultMedium) WriteBlocks(lba uint64, p []byte) error {
	m.mu.Lock()
	failWrite, torn := m.failWrite, m.tornAfter
	m.mu.Unlock()

	if failWrite {
		return errInjected
	}

	if torn >= 0 && torn*BlockSize < len(p) {
		_ = m.MemMedium.WriteBlocks(lba, p[:torn*BlockSize])
		return errInjected
	}

	m.mu.Lock()
	m.dirty = true
	m.mu.Unlock()

	return m.MemMedium.WriteBlocks(lba, p)
}

func (m *faultMedium) Sync() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failSync {
		return errInjected
	}

	m.dirty = false

	return nil
}

func (m *faultMedium) set(fn func(m *faultMedium)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fn(m)
}

// faultHeads fails Store on demand and counts successful stores.
type faultHeads struct {
	*MemHeadStore
	mu     sync.Mutex
	fail   bool
	stores []Head
	// onStore runs before each Store attempt
	onStore func()
}

func (h *faultHeads) Store(head Head) error {
	if h.onStore != nil {
		h.onStore()
	}

	h.mu.Lock()
	fail := h.fail
	h.mu.Unlock()

	if fail {
		return errInjected
	}

	h.mu.Lock()
	h.stores = append(h.stores, head)
	h.mu.Unlock()

	return h.MemHeadStore.Store(head)
}

func (h *faultHeads) setFail(v bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.fail = v
}

func newFaultFixture(t *testing.T, slots int) (*fixture, *faultMedium, *faultHeads) {
	t.Helper()

	f := newFixture(t, slots)
	fm := newFaultMedium(testBlocks(slots))
	fh := &faultHeads{MemHeadStore: f.heads}
	f.medium = fm.MemMedium

	return f, fm, fh
}

func TestTornFinalWrite(t *testing.T) {
	t.Parallel()

	for torn := range RecordBlocks {
		f, fm, fh := newFaultFixture(t, 8)

		w, err := Open(fm, fh, f.id)
		if err != nil {
			t.Fatal(err)
		}

		f.fill(t, w, 2)
		fm.set(func(m *faultMedium) { m.tornAfter = torn })

		if _, err := w.Append(bodyRecord(3)); !errors.Is(err, errInjected) {
			t.Fatalf("torn after %d blocks: got %v, want the injected failure", torn, err)
		}

		if head, _ := f.heads.Load(); head.Seq != 2 {
			t.Errorf("torn %d: head advanced to %d", torn, head.Seq)
		}

		log, err := f.verify(t, f.pub)
		if torn > 0 && !errors.Is(err, ErrTornTail) {
			t.Errorf("torn %d: got %v, want ErrTornTail", torn, err)
		}

		if torn == 0 && err != nil {
			t.Errorf("nothing written: got %v", err)
		}

		if log == nil || len(log.Entries) != 2 {
			t.Fatalf("torn %d: want the 2 complete entries back", torn)
		}

		// a restart accepts the card and the next append reuses the slot
		fm.set(func(m *faultMedium) { m.tornAfter = -1 })

		w, err = Open(fm, fh, f.id)
		if err != nil {
			t.Fatalf("torn %d: reopen: %v", torn, err)
		}

		if e, err := w.Append(bodyRecord(4)); err != nil || e.Seq != 3 {
			t.Fatalf("torn %d: append after tear: seq %d err %v", torn, e.Seq, err)
		}

		if log, err := f.verify(t, f.pub); err != nil || len(log.Entries) != 3 {
			t.Fatalf("torn %d: verify after repair: %v", torn, err)
		}
	}
}

func TestWriteFailureRefusesAndKeepsHead(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"write", "sync"} {
		f, fm, fh := newFaultFixture(t, 8)

		w, err := Open(fm, fh, f.id)
		if err != nil {
			t.Fatal(err)
		}

		f.fill(t, w, 1)
		before := len(fh.stores)

		fm.set(func(m *faultMedium) {
			m.failWrite = mode == "write"
			m.failSync = mode == "sync"
		})

		if _, err := w.Append(bodyRecord(2)); !errors.Is(err, errInjected) {
			t.Fatalf("%s: got %v, want the injected failure", mode, err)
		}

		if len(fh.stores) != before {
			t.Errorf("%s: head store written after a failed medium write", mode)
		}

		if w.Head().Seq != 1 {
			t.Errorf("%s: writer head moved to %d", mode, w.Head().Seq)
		}

		fm.set(func(m *faultMedium) { m.failWrite, m.failSync = false, false })

		if e, err := w.Append(bodyRecord(3)); err != nil || e.Seq != 2 {
			t.Fatalf("%s: retry: seq %d err %v", mode, e.Seq, err)
		}
	}
}

func TestHeadStoredOnlyAfterSync(t *testing.T) {
	t.Parallel()

	f, fm, fh := newFaultFixture(t, 8)

	w, err := Open(fm, fh, f.id)
	if err != nil {
		t.Fatal(err)
	}

	fh.mu.Lock()
	fh.stores = nil
	fh.mu.Unlock()

	// the sync fails: the entry may be on the medium but the head must not
	// move
	fm.set(func(m *faultMedium) { m.failSync = true })

	if _, err := w.Append(bodyRecord(1)); !errors.Is(err, errInjected) {
		t.Fatalf("got %v", err)
	}

	if len(fh.stores) != 0 {
		t.Fatal("head advanced although sync failed")
	}

	// at the moment the head is stored the entry must be on the medium and
	// every write synced
	f.mutate(t, func(img []byte) { clear(img[slotOffset(1) : slotOffset(1)+RecordSize]) })
	fm.set(func(m *faultMedium) { m.failSync, m.dirty = false, false })

	var onMedium, synced bool

	fh.onStore = func() {
		img := f.medium.Image()
		onMedium = !isZero(img[slotOffset(1) : slotOffset(1)+RecordSize])

		fm.mu.Lock()
		synced = !fm.dirty
		fm.mu.Unlock()
	}

	if _, err := w.Append(bodyRecord(1)); err != nil {
		t.Fatal(err)
	}

	if !onMedium || !synced {
		t.Errorf("head stored with entry on medium %t, medium synced %t", onMedium, synced)
	}
}

func TestCrashBetweenMediumAndHeadRecovers(t *testing.T) {
	t.Parallel()

	f, fm, fh := newFaultFixture(t, 8)

	w, err := Open(fm, fh, f.id)
	if err != nil {
		t.Fatal(err)
	}

	f.fill(t, w, 2)

	// the head update fails after the entry is durable
	fh.setFail(true)

	if _, err := w.Append(bodyRecord(3)); !errors.Is(err, errInjected) {
		t.Fatalf("got %v, want the injected failure", err)
	}

	if head, _ := f.heads.Load(); head.Seq != 2 {
		t.Fatalf("head seq %d, want 2", head.Seq)
	}

	// power loss: reopen with the head one behind
	fh.setFail(false)

	w2, err := Open(fm, fh, f.id)
	if err != nil {
		t.Fatalf("open after crash: %v", err)
	}

	if head, _ := f.heads.Load(); head.Seq != 3 || w2.Head() != head {
		t.Fatalf("head not repaired: %+v", head)
	}

	if e, err := w2.Append(bodyRecord(4)); err != nil || e.Seq != 4 {
		t.Fatalf("append after repair: seq %d err %v", e.Seq, err)
	}

	if log, err := f.verify(t, f.pub); err != nil || len(log.Entries) != 4 {
		t.Fatalf("verify: %v", err)
	}
}

func TestFailedHeadStoreIsRetriedBeforeNextAppend(t *testing.T) {
	t.Parallel()

	f, fm, fh := newFaultFixture(t, 8)

	w, err := Open(fm, fh, f.id)
	if err != nil {
		t.Fatal(err)
	}

	f.fill(t, w, 1)
	fh.setFail(true)

	if _, err := w.Append(bodyRecord(2)); !errors.Is(err, errInjected) {
		t.Fatalf("got %v", err)
	}

	// still failing: no further entry may be written ahead of the head
	if _, err := w.Append(bodyRecord(3)); !errors.Is(err, errInjected) {
		t.Fatalf("got %v", err)
	}

	img := f.medium.Image()
	if !bytes.Equal(img[slotOffset(3):slotOffset(3)+RecordSize], make([]byte, RecordSize)) {
		t.Fatal("entry written while the head was two behind")
	}

	fh.setFail(false)

	if e, err := w.Append(bodyRecord(3)); err != nil || e.Seq != 3 {
		t.Fatalf("append after recovery: seq %d err %v", e.Seq, err)
	}

	if head, _ := f.heads.Load(); head.Seq != 3 {
		t.Errorf("head seq %d, want 3", head.Seq)
	}

	if log, err := f.verify(t, f.pub); err != nil || len(log.Entries) != 3 {
		t.Fatalf("verify: %v", err)
	}
}

func TestHeadAheadOfMediumRefused(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	f.fill(t, f.open(t), 3)

	head, _ := f.heads.Load()
	head.Seq = 4
	f.heads.Store(head)

	if _, err := Open(f.medium, f.heads, f.id); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want ErrRollback", err)
	}
}

func TestMediumTwoAheadRefused(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	w := f.open(t)
	f.fill(t, w, 1)

	head, _ := f.heads.Load()
	f.fill(t, w, 2)
	f.heads.Store(head)

	if _, err := Open(f.medium, f.heads, f.id); !errors.Is(err, ErrAhead) {
		t.Fatalf("got %v, want ErrAhead", err)
	}
}

func TestMediumOneAheadMustChain(t *testing.T) {
	t.Parallel()

	// the head names entry 2 of another card; this card's entry 3 does
	// not chain from it
	f := newFixture(t, 8)
	f.fill(t, f.open(t), 3)

	head, _ := f.heads.Load()
	head.Seq, head.Hash = 2, sha256.Sum256([]byte("other card"))
	f.heads.Store(head)

	if _, err := Open(f.medium, f.heads, f.id); !errors.Is(err, ErrAhead) {
		t.Fatalf("got %v, want ErrAhead", err)
	}

	if after, _ := f.heads.Load(); after != head {
		t.Error("head repaired from a non-chaining entry")
	}
}

func TestFullMediumRefuses(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 3)
	w := f.open(t)
	f.fill(t, w, 3)

	head := w.Head()

	if _, err := w.Append(bodyRecord(4)); !errors.Is(err, ErrFull) {
		t.Fatalf("got %v, want ErrFull", err)
	}

	if w.Head() != head {
		t.Error("head moved on a refused append")
	}

	if stored, _ := f.heads.Load(); stored != head {
		t.Error("head store moved on a refused append")
	}

	if log, err := f.verify(t, f.pub); err != nil || len(log.Entries) != 3 {
		t.Fatalf("verify full card: %v", err)
	}

	// still full after a restart
	if _, err := f.open(t).Append(bodyRecord(5)); !errors.Is(err, ErrFull) {
		t.Fatalf("after reopen: got %v, want ErrFull", err)
	}
}

func TestInvalidRecordsRefused(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 300)

	for name, rec := range map[string]Record{
		"unknown purpose":     {Profile: "p", Role: "pool", Purpose: "tx-witness"},
		"tx-body no hash":     {Profile: "p", Role: "pool", Purpose: PurposeTxBody},
		"tx-body short hash":  {Profile: "p", Role: "pool", Purpose: PurposeTxBody, BodyHash: []byte{1}},
		"tx-body with opcert": {Profile: "p", Role: "pool", Purpose: PurposeTxBody, BodyHash: make([]byte, 32), KESPeriod: 1},
		"opcert no kes hash":  {Profile: "p", Role: "pool", Purpose: PurposeOpCertNext},
		"opcert with body":    {Profile: "p", Role: "pool", Purpose: PurposeOpCertNext, KESKeyHash: make([]byte, 32), BodyHash: make([]byte, 32)},
		"huge profile":        {Profile: strings.Repeat("p", 4000), Role: "pool", Purpose: PurposeTxBody, BodyHash: make([]byte, 32)},
		"long role":           {Profile: "p", Role: long, Purpose: PurposeTxBody, BodyHash: make([]byte, 32)},
	} {
		f := newFixture(t, 4)
		w := f.open(t)

		if _, err := w.Append(rec); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("%s: got %v, want ErrInvalidRecord", name, err)
		}

		if w.Head().Seq != 0 {
			t.Errorf("%s: head moved", name)
		}
	}
}

func TestLongSummaryIsCutOnARuneBoundary(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 4)
	w := f.open(t)

	rec := bodyRecord(1)
	rec.Summary = strings.Repeat("é", MaxSummary) // two bytes each

	e, err := w.Append(rec)
	if err != nil {
		t.Fatal(err)
	}

	if len(e.Summary) > MaxSummary || !utf8.ValidString(e.Summary) || len(e.Summary) < MaxSummary-4 {
		t.Fatalf("summary of %d bytes", len(e.Summary))
	}

	log, err := f.verify(t, f.pub)
	if err != nil || log.Entries[0].Summary != e.Summary {
		t.Fatalf("verify: %v", err)
	}
}

func TestTruncationIsRecordedAndSigned(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 8)
	w := f.open(t)

	short := bodyRecord(1)

	long := bodyRecord(2)
	long.Summary = strings.Repeat("x", MaxSummary+1)

	exact := bodyRecord(3)
	exact.Summary = strings.Repeat("x", MaxSummary)

	var got []Entry

	for _, rec := range []Record{short, long, exact} {
		e, err := w.Append(rec)
		if err != nil {
			t.Fatal(err)
		}

		got = append(got, e)
	}

	for i, want := range []bool{false, true, false} {
		if got[i].SummaryTruncated != want {
			t.Errorf("entry %d: SummaryTruncated=%v, want %v", i+1, got[i].SummaryTruncated, want)
		}
	}

	log, err := f.verify(t, f.pub)
	if err != nil {
		t.Fatal(err)
	}

	for i, want := range []bool{false, true, false} {
		if log.Entries[i].SummaryTruncated != want {
			t.Errorf("verified entry %d: SummaryTruncated=%v, want %v", i+1, log.Entries[i].SummaryTruncated, want)
		}
	}

	// the flag is covered by the signature: clearing it must not verify
	forged := log.Entries[1]
	forged.SummaryTruncated = false

	if err := verifyEntry(forged, f.pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("flag cleared: %v, want ErrBadSignature", err)
	}
}

func TestConcurrentAppendsSerialise(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 32)
	w := f.open(t)

	var wg sync.WaitGroup

	for i := range 20 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, err := w.Append(bodyRecord(byte(i))); err != nil {
				t.Errorf("append: %v", err)
			}
		}()
	}

	wg.Wait()

	if log, err := f.verify(t, f.pub); err != nil || len(log.Entries) != 20 {
		t.Fatalf("verify: %v", err)
	}
}

func TestUndersizedMediumRefused(t *testing.T) {
	t.Parallel()

	f := newFixture(t, 4)
	f.open(t)

	small := NewMemMedium(5)
	copy(small.img, f.medium.Image())

	if _, err := Verify(small, f.pub); !errors.Is(err, ErrMedium) {
		t.Fatalf("verify: got %v, want ErrMedium", err)
	}

	if _, err := Open(NewMemMedium(1), NewMemHeadStore(Head{}), f.id); !errors.Is(err, ErrMedium) {
		t.Fatalf("open: got %v, want ErrMedium", err)
	}
}
