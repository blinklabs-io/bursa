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
	"crypto/sha256"
	"fmt"
	"sync"
)

// Writer appends entries to a medium that matched the head store at Open.
type Writer struct {
	mu     sync.Mutex
	medium Medium
	heads  HeadStore
	id     Identity
	hdr    Header
	head   Head
	// pending is a head that reached the medium but not yet the head store
	pending *Head
}

// Open checks the medium against the head store and returns a writer.
//
// A blank medium is formatted with a header for id when the head store is
// uninitialised (the zero Head), and refused otherwise; its record slots
// must be all zero too (ErrNotBlank). Otherwise the
// header must name id, and the latest entry on the medium is compared with
// the head: equal is accepted; a medium behind the head (an older copy, a
// truncated or torn latest record) is ErrRollback; a differing hash with the
// same number is ErrHashMismatch; a medium exactly one entry ahead is the
// remnant of a crash between medium write and head update and is accepted
// when that entry chains from the head, after which the head is repaired;
// any other medium ahead of the head is ErrAhead. An uninitialised head
// accepts only a medium without entries. Open checks the chain and the last
// entry's signature; Verify checks every signature.
func Open(m Medium, hs HeadStore, id Identity) (*Writer, error) {
	head, err := hs.Load()
	if err != nil {
		return nil, fmt.Errorf("signlog: load head: %w", err)
	}

	w := &Writer{medium: m, heads: hs, id: id}

	if isBlankHeader(m) {
		return w.format(head)
	}

	hdr, err := readHeader(m, nil)
	if err != nil {
		return nil, err
	}

	if string(hdr.Identity) != string(id.Public()) {
		return nil, ErrWrongDevice
	}

	entries, _, err := scan(m, hdr, false, false)
	if err != nil {
		return nil, err
	}

	w.hdr = hdr
	last := headOf(hdr, entries)

	switch {
	case head == (Head{}):
		if last.Seq != 0 {
			return nil, fmt.Errorf("%w: head store is uninitialised but the medium holds %d entries", ErrAhead, last.Seq)
		}

		return w, w.repair(last)
	case last.Seq < head.Seq:
		return nil, fmt.Errorf("%w: medium at entry %d, head at %d", ErrRollback, last.Seq, head.Seq)
	case last.Seq == head.Seq:
		if last.Hash != head.Hash {
			return nil, ErrHashMismatch
		}

		w.head = head

		return w, nil
	case last.Seq == head.Seq+1 && entries[len(entries)-1].Prev == head.Hash:
		return w, w.repair(last)
	}

	return nil, fmt.Errorf("%w: medium at entry %d, head at %d", ErrAhead, last.Seq, head.Seq)
}

// isBlankHeader reports whether block 0 is all zero.
func isBlankHeader(m Medium) bool {
	block := make([]byte, BlockSize)

	return m.NumBlocks() >= 1 && m.ReadBlocks(0, block) == nil && isZero(block)
}

// repair stores head and adopts it.
func (w *Writer) repair(head Head) error {
	if err := w.heads.Store(head); err != nil {
		return fmt.Errorf("signlog: store head: %w", err)
	}

	w.head = head

	return nil
}

// format writes a header for a blank medium.
func (w *Writer) format(head Head) (*Writer, error) {
	if head != (Head{}) {
		return nil, ErrBlank
	}

	slots := min((w.medium.NumBlocks()-1)/RecordBlocks, DefaultMaxEntries)
	if w.medium.NumBlocks() < 1 || slots == 0 {
		return nil, fmt.Errorf("%w: %d blocks hold no entry", ErrMedium, w.medium.NumBlocks())
	}

	if err := checkBlank(w.medium, 1+slots*RecordBlocks); err != nil {
		return nil, err
	}

	block, err := formatHeader(w.id, slots)
	if err != nil {
		return nil, err
	}

	if err = w.medium.WriteBlocks(0, block); err != nil {
		return nil, fmt.Errorf("signlog: write header: %w", err)
	}

	if err = w.medium.Sync(); err != nil {
		return nil, fmt.Errorf("signlog: sync header: %w", err)
	}

	if w.hdr, err = parseHeader(block, w.id.Public()); err != nil {
		return nil, err
	}

	return w, w.repair(Head{Hash: sha256.Sum256(block)})
}

// blankChunk is the number of blocks checkBlank reads at once.
const blankChunk = 256

// checkBlank confirms the first n blocks of m are all zero, so nothing but
// zeros follows the entries the writer will add, as Verify requires.
func checkBlank(m Medium, n uint64) error {
	buf := make([]byte, blankChunk*BlockSize)

	for lba := uint64(0); lba < n; lba += blankChunk {
		p := buf[:min(blankChunk, n-lba)*BlockSize]
		if err := m.ReadBlocks(lba, p); err != nil {
			return fmt.Errorf("%w: read block %d: %w", ErrMedium, lba, err)
		}

		if !isZero(p) {
			return fmt.Errorf("%w: data in blocks %d+%d", ErrNotBlank, lba, len(p)/BlockSize)
		}
	}

	return nil
}

// Head returns the latest entry the writer has logged.
func (w *Writer) Head() Head {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.head
}

// Append logs rec and returns the entry. The entry is on the medium, synced,
// and the head store updated before it returns; only then may the caller
// release the signature. On any error nothing may be released. A medium
// write failure leaves the head store untouched; a failed head update is
// retried before the next entry is written, so the medium is never more than
// one entry ahead of the head store.
func (w *Writer) Append(rec Record) (Entry, error) {
	rec, err := normalize(rec)
	if err != nil {
		return Entry{}, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.pending != nil {
		if err = w.heads.Store(*w.pending); err != nil {
			return Entry{}, fmt.Errorf("signlog: store head: %w", err)
		}

		w.pending = nil
	}

	if w.head.Seq >= w.hdr.Entries {
		return Entry{}, ErrFull
	}

	if err = w.recheck(); err != nil {
		return Entry{}, err
	}

	raw, err := frameEntry(Entry{Record: rec, Seq: w.head.Seq + 1, Prev: w.head.Hash}, w.id)
	if err != nil {
		return Entry{}, err
	}

	e, err := decodeRecord(raw)
	if err != nil {
		return Entry{}, fmt.Errorf("signlog: framed entry unreadable: %w", err)
	}

	if err = verifyEntry(e, w.hdr.Identity); err != nil {
		return Entry{}, err
	}

	if err = w.medium.WriteBlocks(slotLBA(e.Seq), raw); err != nil {
		return Entry{}, fmt.Errorf("signlog: write entry %d: %w", e.Seq, err)
	}

	if err = w.medium.Sync(); err != nil {
		return Entry{}, fmt.Errorf("signlog: sync entry %d: %w", e.Seq, err)
	}

	next := Head{Seq: e.Seq, Hash: e.Hash}
	w.head, w.pending = next, &next

	if err = w.heads.Store(next); err != nil {
		return Entry{}, fmt.Errorf("signlog: store head: %w", err)
	}

	w.pending = nil

	return e, nil
}

// recheck confirms the head store and the medium's latest entry still match
// the writer's head, so a card swapped while running is caught before a
// write.
func (w *Writer) recheck() error {
	stored, err := w.heads.Load()
	if err != nil {
		return fmt.Errorf("signlog: load head: %w", err)
	}

	if stored != w.head {
		return ErrHeadStore
	}

	if w.head.Seq == 0 {
		block := make([]byte, BlockSize)
		if err = w.medium.ReadBlocks(0, block); err != nil {
			return fmt.Errorf("%w: read header: %w", ErrMedium, err)
		}

		if sha256.Sum256(block) != w.head.Hash {
			return ErrHashMismatch
		}

		return nil
	}

	buf := make([]byte, RecordSize)
	if err = w.medium.ReadBlocks(slotLBA(w.head.Seq), buf); err != nil {
		return fmt.Errorf("%w: read entry %d: %w", ErrMedium, w.head.Seq, err)
	}

	e, err := decodeRecord(buf)
	if err != nil {
		return fmt.Errorf("%w: entry %d unreadable: %w", ErrRollback, w.head.Seq, err)
	}

	if e.Seq != w.head.Seq || e.Hash != w.head.Hash {
		return ErrHashMismatch
	}

	return nil
}
