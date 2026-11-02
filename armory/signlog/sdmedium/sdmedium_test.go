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
	"fmt"
	"slices"
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
	// onDetect runs on every Detect, as when a card is swapped
	onDetect func(*fakeCard)
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
	// largest is the largest transfer in bytes
	largest int
	// readBytes is the total bytes read
	readBytes int
	// calls logs every transfer in order
	calls []transfer
	// fail, when set, fails the transfers it returns true for
	fail func(transfer) bool
}

// transfer is one card call: the operation, the first block and the block
// count.
type transfer struct {
	op     string
	lba    int
	blocks int
}

// log records a transfer and checks it lies on the card in whole blocks.
func (c *fakeCard) log(op string, lba int, buf []byte) error {
	tr := transfer{op: op, lba: lba, blocks: len(buf) / signlog.BlockSize}
	c.calls = append(c.calls, tr)

	if lba < 0 || len(buf)%signlog.BlockSize != 0 || lba*signlog.BlockSize+len(buf) > len(c.img) {
		return fmt.Errorf("%s of %d bytes at block %d is off the card", op, len(buf), lba)
	}

	if c.fail != nil && c.fail(tr) {
		return fmt.Errorf("%s failed at block %d", op, lba)
	}

	return nil
}

func newFakeCard(blocks int) *fakeCard {
	return &fakeCard{img: make([]byte, blocks*signlog.BlockSize), blockSize: signlog.BlockSize}
}

func (c *fakeCard) Detect() error {
	c.detects++

	if c.onDetect != nil {
		c.onDetect(c)
	}

	return c.detectErr
}

func (c *fakeCard) Geometry() (int, uint64) {
	return c.blockSize, uint64(len(c.img) / signlog.BlockSize)
}

func (c *fakeCard) ReadBlocks(lba int, buf []byte) error {
	c.reads++
	c.largest = max(c.largest, len(buf))
	c.readBytes += len(buf)

	if err := c.log("read", lba, buf); err != nil {
		return err
	}

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
	c.largest = max(c.largest, len(buf))

	if err := c.log("write", lba, buf); err != nil {
		return err
	}

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

// chunks lists consecutive transfers from lba of the given block counts.
func chunks(op string, lba int, sizes ...int) []transfer {
	out := make([]transfer, 0, len(sizes))
	for _, n := range sizes {
		out = append(out, transfer{op: op, lba: lba, blocks: n})
		lba += n
	}

	return out
}

func randomBlocks(t *testing.T, n int) []byte {
	t.Helper()

	data := make([]byte, n*signlog.BlockSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	return data
}

func TestTransfersAreSplit(t *testing.T) {
	t.Parallel()

	// the controller's DMA buffers come from a small on-chip region, so a
	// large transfer must reach the card in pieces of at most
	// MaxTransferBlocks
	const lba = 5

	tests := []struct {
		name   string
		blocks int
		sizes  []int
	}{
		{"one block", 1, []int{1}},
		{"one under the limit", MaxTransferBlocks - 1, []int{MaxTransferBlocks - 1}},
		{"at the limit", MaxTransferBlocks, []int{MaxTransferBlocks}},
		{"one over the limit", MaxTransferBlocks + 1, []int{MaxTransferBlocks, 1}},
		{"twice the limit", 2 * MaxTransferBlocks, []int{MaxTransferBlocks, MaxTransferBlocks}},
		{"many pieces", 300, append(slices.Repeat([]int{MaxTransferBlocks}, 300/MaxTransferBlocks), 300%MaxTransferBlocks)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// the transfer ends on the card's last block
			c := newFakeCard(lba + tc.blocks)
			m := open(t, c)
			data := randomBlocks(t, tc.blocks)

			if err := m.WriteBlocks(lba, data); err != nil {
				t.Fatal(err)
			}

			if want := chunks("write", lba, tc.sizes...); !slices.Equal(c.calls, want) {
				t.Fatalf("write calls %v, want %v", c.calls, want)
			}

			if !bytes.Equal(c.img[lba*signlog.BlockSize:], data) {
				t.Fatal("card image differs from the data written")
			}

			c.calls = nil

			if err := m.Sync(); err != nil {
				t.Fatal(err)
			}

			if want := chunks("read", lba, tc.sizes...); !slices.Equal(c.calls, want) {
				t.Fatalf("sync calls %v, want %v", c.calls, want)
			}

			c.calls = nil
			got := make([]byte, len(data))

			if err := m.ReadBlocks(lba, got); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("read back: %v", err)
			}

			if want := chunks("read", lba, tc.sizes...); !slices.Equal(c.calls, want) {
				t.Fatalf("read calls %v, want %v", c.calls, want)
			}
		})
	}
}

// A transfer whose second piece fails is re-run from the first piece after
// the re-detect, so a swapped card receives every piece.
func TestSplitWriteRetriesEveryPiece(t *testing.T) {
	t.Parallel()

	const lba = 5

	n := 2*MaxTransferBlocks + 1
	c := newFakeCard(lba + n)
	m := open(t, c)
	data := randomBlocks(t, n)

	second := lba + MaxTransferBlocks
	failed := false
	c.fail = func(tr transfer) bool {
		if tr.lba != second || failed {
			return false
		}
		failed = true

		return true
	}
	// the re-detected card is blank, so a piece the retry skips is lost
	c.onDetect = func(c *fakeCard) { c.img = make([]byte, len(c.img)) }

	if err := m.WriteBlocks(lba, data); err != nil {
		t.Fatalf("write after a transient error: %v", err)
	}

	want := append(chunks("write", lba, MaxTransferBlocks, MaxTransferBlocks),
		chunks("write", lba, MaxTransferBlocks, MaxTransferBlocks, 1)...)
	if !slices.Equal(c.calls, want) {
		t.Fatalf("write calls %v, want %v", c.calls, want)
	}

	if !bytes.Equal(c.img[lba*signlog.BlockSize:], data) {
		t.Fatal("card image differs from the data written")
	}

	// the write needed a re-detect, so it is not trusted
	if err := m.Sync(); !errors.Is(err, ErrRedetected) {
		t.Fatalf("sync: %v, want ErrRedetected", err)
	}
}

// A second piece that keeps failing fails the write, stops before the third
// piece and leaves nothing for Sync to verify.
func TestSplitWritePersistentFailure(t *testing.T) {
	t.Parallel()

	const lba = 5

	n := 2*MaxTransferBlocks + 1
	c := newFakeCard(lba + n)
	m := open(t, c)
	second := lba + MaxTransferBlocks
	c.fail = func(tr transfer) bool { return tr.lba == second }

	if err := m.WriteBlocks(lba, randomBlocks(t, n)); err == nil {
		t.Fatal("a persistent write failure was not reported")
	}

	want := slices.Repeat(chunks("write", lba, MaxTransferBlocks, MaxTransferBlocks), 2)
	if !slices.Equal(c.calls, want) {
		t.Fatalf("write calls %v, want %v", c.calls, want)
	}

	c.calls = nil

	if err := m.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	if len(c.calls) != 0 {
		t.Fatalf("sync read back a failed write: %v", c.calls)
	}
}

// A read whose second piece fails is re-run from the first piece after the
// re-detect, so every piece comes from the card now in the slot.
func TestSplitReadRetriesEveryPiece(t *testing.T) {
	t.Parallel()

	const lba = 5

	n := 2*MaxTransferBlocks + 1
	c := newFakeCard(lba + n)
	m := open(t, c)
	stale := randomBlocks(t, n)
	copy(c.img[lba*signlog.BlockSize:], stale)
	fresh := randomBlocks(t, n)

	second := lba + MaxTransferBlocks
	failed := false
	c.fail = func(tr transfer) bool {
		if tr.lba != second || failed {
			return false
		}
		failed = true

		return true
	}
	// the re-detected card holds other data, so a piece the retry skips
	// keeps what the first card returned
	c.onDetect = func(c *fakeCard) { copy(c.img[lba*signlog.BlockSize:], fresh) }

	got := make([]byte, n*signlog.BlockSize)
	if err := m.ReadBlocks(lba, got); err != nil {
		t.Fatalf("read after a transient error: %v", err)
	}

	want := append(chunks("read", lba, MaxTransferBlocks, MaxTransferBlocks),
		chunks("read", lba, MaxTransferBlocks, MaxTransferBlocks, 1)...)
	if !slices.Equal(c.calls, want) {
		t.Fatalf("read calls %v, want %v", c.calls, want)
	}

	if !bytes.Equal(got, fresh) {
		t.Fatal("read returned data from before the re-detect")
	}
}

// A second piece that keeps failing fails the read and stops before the
// third piece.
func TestSplitReadPersistentFailure(t *testing.T) {
	t.Parallel()

	const lba = 5

	n := 2*MaxTransferBlocks + 1
	c := newFakeCard(lba + n)
	m := open(t, c)
	second := lba + MaxTransferBlocks
	c.fail = func(tr transfer) bool { return tr.lba == second }

	if err := m.ReadBlocks(lba, make([]byte, n*signlog.BlockSize)); err == nil {
		t.Fatal("a persistent read failure was not reported")
	}

	want := slices.Repeat(chunks("read", lba, MaxTransferBlocks, MaxTransferBlocks), 2)
	if !slices.Equal(c.calls, want) {
		t.Fatalf("read calls %v, want %v", c.calls, want)
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

func TestFormatSplitsTransfers(t *testing.T) {
	t.Parallel()

	// formatting checks the record slots are blank in large reads
	c := newFakeCard(1 + 300*signlog.RecordBlocks)
	m := open(t, c)

	if _, err := signlog.Open(m, signlog.NewMemHeadStore(signlog.Head{}), newIdentity(t)); err != nil {
		t.Fatal(err)
	}

	if want := MaxTransferBlocks * signlog.BlockSize; c.largest > want {
		t.Fatalf("largest transfer %d bytes, want at most %d", c.largest, want)
	}

	// the blank check read every record slot
	if want := (1 + 300*signlog.RecordBlocks) * signlog.BlockSize; c.readBytes < want {
		t.Fatalf("read %d bytes, want at least %d", c.readBytes, want)
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

// A write that only succeeded after the card was re-detected may have gone
// to a different card than the one the writer checked, so Sync fails and the
// head stays where it was.
func TestRedetectedWriteFailsSync(t *testing.T) {
	t.Parallel()

	c := newFakeCard(1 + 8*signlog.RecordBlocks)
	m := open(t, c)
	id := newIdentity(t)
	heads := signlog.NewMemHeadStore(signlog.Head{})

	w, err := signlog.Open(m, heads, id)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = w.Append(record()); err != nil {
		t.Fatal(err)
	}

	before := w.Head()

	// the next write fails once and the card is swapped for a blank one
	c.failWrites = 1
	c.onDetect = func(c *fakeCard) {
		c.img = make([]byte, len(c.img))
		c.onDetect = nil
	}

	if _, err = w.Append(record()); err == nil {
		t.Fatal("append succeeded on a card swapped during the write")
	}

	if stored, _ := heads.Load(); stored != before || w.Head() != before {
		t.Fatalf("head moved to %+v", stored)
	}

	// the swapped card is caught before the next write
	if _, err = w.Append(record()); err == nil {
		t.Fatal("append succeeded on the swapped card")
	}
}
