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
	"crypto/ed25519"
	"errors"
	"fmt"
)

// scan reads the record slots in order and returns the entries up to the
// first blank or torn slot. Each entry must carry the next sequence number
// and chain from its predecessor. Signatures are checked on every entry
// when allSigs is set, otherwise on the last only; the chain hashes cover
// the rest. With strict set, everything after the end must be blank, except
// that one torn record may sit directly at the end, reported as torn.
func scan(m Medium, h Header, allSigs, strict bool) (entries []Entry, torn bool, err error) {
	buf := make([]byte, RecordSize)
	prev := h.Hash
	end := h.Entries + 1 // first slot not holding an entry

	for seq := uint64(1); seq <= h.Entries; seq++ {
		if err = m.ReadBlocks(slotLBA(seq), buf); err != nil {
			return nil, false, fmt.Errorf("%w: read entry %d: %w", ErrMedium, seq, err)
		}

		e, derr := decodeRecord(buf)
		if errors.Is(derr, errBlankSlot) || errors.Is(derr, errTorn) {
			torn = errors.Is(derr, errTorn)
			end = seq

			break
		}

		if derr != nil {
			return nil, false, fmt.Errorf("entry %d: %w", seq, derr)
		}

		if e.Seq != seq {
			return nil, false, fmt.Errorf("%w: slot %d holds entry %d", ErrSequence, seq, e.Seq)
		}

		if e.Prev != prev {
			return nil, false, fmt.Errorf("%w: entry %d", ErrChain, seq)
		}

		if allSigs {
			if err = verifyEntry(e, h.Identity); err != nil {
				return nil, false, err
			}
		}

		entries, prev = append(entries, e), e.Hash
	}

	if n := len(entries); n > 0 && !allSigs {
		if err = verifyEntry(entries[n-1], h.Identity); err != nil {
			return nil, false, err
		}
	}

	if !strict {
		return entries, torn, nil
	}

	// a torn record is the end only if nothing follows it
	for seq := end + 1; seq <= h.Entries; seq++ {
		if err = m.ReadBlocks(slotLBA(seq), buf); err != nil {
			return nil, false, fmt.Errorf("%w: read entry %d: %w", ErrMedium, seq, err)
		}

		if !isZero(buf) {
			return nil, false, fmt.Errorf("%w: slot %d", ErrTrailing, seq)
		}
	}

	return entries, torn, nil
}

// readHeader reads and checks the header block, and that the medium holds
// every slot it declares.
func readHeader(m Medium, pub ed25519.PublicKey) (Header, error) {
	block := make([]byte, BlockSize)

	if m.NumBlocks() < 1 {
		return Header{}, fmt.Errorf("%w: no header block", ErrMedium)
	}

	if err := m.ReadBlocks(0, block); err != nil {
		return Header{}, fmt.Errorf("%w: read header: %w", ErrMedium, err)
	}

	if isZero(block) {
		return Header{}, fmt.Errorf("%w: blank medium", ErrCorrupt)
	}

	h, err := parseHeader(block, pub)
	if err != nil {
		return h, err
	}

	if m.NumBlocks() < slotLBA(h.Entries)+RecordBlocks {
		return h, fmt.Errorf("%w: header declares %d slots, medium holds %d blocks", ErrMedium, h.Entries, m.NumBlocks())
	}

	return h, nil
}

// Verify checks the whole record on m against the pinned identity key: the
// header names the identity and is signed by it, every entry's signature
// verifies, sequence numbers run from 1 without gaps, each entry chains from
// the previous one, and nothing but zeros follows the last entry. An
// incomplete final record is returned as ErrTornTail together with the
// entries before it. Verify cannot tell a card from an older copy of
// itself; only the head store can.
func Verify(m Medium, identity ed25519.PublicKey) (*Log, error) {
	if len(identity) != ed25519.PublicKeySize {
		return nil, errors.New("signlog: invalid identity public key")
	}

	h, err := readHeader(m, identity)
	if err != nil {
		return nil, err
	}

	entries, torn, err := scan(m, h, true, true)
	if err != nil {
		return nil, err
	}

	log := &Log{Header: h, Entries: entries}
	if torn {
		return log, ErrTornTail
	}

	return log, nil
}

// Head returns the head naming the last entry, or the header when there is
// none: what the head store holds for this log.
func (l *Log) Head() Head { return headOf(l.Header, l.Entries) }

// headOf returns the head naming the last of entries, or the header.
func headOf(h Header, entries []Entry) Head {
	if n := len(entries); n > 0 {
		return Head{Seq: entries[n-1].Seq, Hash: entries[n-1].Hash}
	}

	return Head{Hash: h.Hash}
}
