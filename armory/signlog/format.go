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
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

const (
	headerMagic = "BURSALOG"
	recordMagic = "BSLE"

	// header fields
	hdrVersionOff  = 8
	hdrBlockOff    = 12
	hdrRecBlocksOf = 16
	hdrReservedOff = 20
	hdrEntriesOff  = 24
	hdrCardOff     = 32
	hdrIdentityOff = 48
	hdrSignedLen   = 80
	hdrSigOff      = 80
	hdrUsedLen     = 144

	// record fields
	recLenOff     = 4
	recPayloadOff = 6
	recSigOff     = RecordSize - sha256.Size - ed25519.SignatureSize
	recSumOff     = RecordSize - sha256.Size
	maxPayload    = recSigOff - recPayloadOff

	maxName = 128

	// domains separate the identity key's log signatures from every other
	// signature it makes, and the entry hash from the signed digest
	signDomain   = "bursa-armory-signlog-entry/1"
	linkDomain   = "bursa-armory-signlog-link/1"
	headerDomain = "bursa-armory-signlog-header/1"
)

var (
	// errBlankSlot marks an all-zero block range.
	errBlankSlot = errors.New("signlog: blank")
	// errTorn marks a record whose checksum fails.
	errTorn = errors.New("signlog: torn record")

	encMode = func() cbor.EncMode {
		m, err := cbor.CoreDetEncOptions().EncMode()
		if err != nil {
			panic(err)
		}

		return m
	}()
)

// payload is the signed content of an entry, a CBOR array.
type payload struct {
	_            struct{} `cbor:",toarray"`
	Seq          uint64
	Prev         []byte
	Profile      string
	Role         string
	Purpose      string
	BodyHash     []byte
	Summary      string
	IssueCounter uint64
	KESPeriod    uint64
	KESKeyHash   []byte
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}

	return true
}

func orNil(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}

	return b
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}

	return s[:n]
}

// normalize validates rec for its purpose and cuts the summary.
func normalize(rec Record) (Record, error) {
	rec.BodyHash, rec.KESKeyHash = orNil(rec.BodyHash), orNil(rec.KESKeyHash)
	rec.Summary = truncate(rec.Summary, MaxSummary)

	for _, s := range []string{rec.Profile, rec.Role, rec.Purpose} {
		if len(s) > maxName {
			return rec, fmt.Errorf("%w: name of %d bytes", ErrInvalidRecord, len(s))
		}
	}

	switch rec.Purpose {
	case PurposeTxBody:
		if len(rec.BodyHash) != HashSize || rec.IssueCounter != 0 || rec.KESPeriod != 0 || rec.KESKeyHash != nil {
			return rec, fmt.Errorf("%w: tx-body needs a %d-byte body hash and no opcert fields", ErrInvalidRecord, HashSize)
		}
	case PurposeOpCertNext:
		if len(rec.KESKeyHash) != HashSize || rec.BodyHash != nil {
			return rec, fmt.Errorf("%w: opcert-next needs a %d-byte KES key hash and no body hash", ErrInvalidRecord, HashSize)
		}
	default:
		return rec, fmt.Errorf("%w: purpose %q", ErrInvalidRecord, rec.Purpose)
	}

	return rec, nil
}

func (e Entry) payload() payload {
	return payload{
		Seq: e.Seq, Prev: e.Prev[:], Profile: e.Profile, Role: e.Role,
		Purpose: e.Purpose, BodyHash: orNil(e.BodyHash), Summary: e.Summary,
		IssueCounter: e.IssueCounter, KESPeriod: e.KESPeriod, KESKeyHash: orNil(e.KESKeyHash),
	}
}

func signDigest(enc []byte) []byte {
	h := sha256.New()
	h.Write([]byte(signDomain))
	h.Write(enc)

	return h.Sum(nil)
}

func linkHash(enc, sig []byte) (out [HashSize]byte) {
	h := sha256.New()
	h.Write([]byte(linkDomain))
	h.Write(enc)
	h.Write(sig)
	h.Sum(out[:0])

	return out
}

// frameEntry encodes, signs and frames e into one record.
func frameEntry(e Entry, id Identity) ([]byte, error) {
	rec, err := normalize(e.Record)
	if err != nil {
		return nil, err
	}

	e.Record = rec

	enc, err := encMode.Marshal(e.payload())
	if err != nil {
		return nil, fmt.Errorf("signlog: encode entry: %w", err)
	}

	if len(enc) > maxPayload {
		return nil, fmt.Errorf("%w: payload of %d bytes", ErrInvalidRecord, len(enc))
	}

	sig, err := id.Sign(signDigest(enc))
	if err != nil {
		return nil, fmt.Errorf("signlog: sign entry: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signlog: identity returned a %d-byte signature", len(sig))
	}

	out := make([]byte, RecordSize)
	copy(out, recordMagic)
	binary.BigEndian.PutUint16(out[recLenOff:], uint16(len(enc))) //nolint:gosec // bounded by maxPayload
	copy(out[recPayloadOff:], enc)
	copy(out[recSigOff:], sig)

	sum := sha256.Sum256(out[:recSumOff])
	copy(out[recSumOff:], sum[:])

	return out, nil
}

// decodeRecord parses one slot. It returns errBlankSlot for an all-zero
// slot and errTorn when the checksum fails; any other failure is ErrCorrupt.
// It does not check the signature.
func decodeRecord(slot []byte) (Entry, error) {
	var e Entry

	if isZero(slot) {
		return e, errBlankSlot
	}

	sum := sha256.Sum256(slot[:recSumOff])
	if !bytes.Equal(sum[:], slot[recSumOff:]) {
		return e, errTorn
	}

	if string(slot[:len(recordMagic)]) != recordMagic {
		return e, fmt.Errorf("%w: record magic", ErrCorrupt)
	}

	n := int(binary.BigEndian.Uint16(slot[recLenOff:]))
	if n == 0 || n > maxPayload || !isZero(slot[recPayloadOff+n:recSigOff]) {
		return e, fmt.Errorf("%w: record length %d", ErrCorrupt, n)
	}

	enc := slot[recPayloadOff : recPayloadOff+n]

	var p payload
	if err := cbor.Unmarshal(enc, &p); err != nil {
		return e, fmt.Errorf("%w: record payload: %w", ErrCorrupt, err)
	}

	if len(p.Prev) != HashSize {
		return e, fmt.Errorf("%w: previous hash of %d bytes", ErrCorrupt, len(p.Prev))
	}

	e = Entry{
		Record: Record{
			Profile: p.Profile, Role: p.Role, Purpose: p.Purpose,
			BodyHash: orNil(p.BodyHash), Summary: p.Summary,
			IssueCounter: p.IssueCounter, KESPeriod: p.KESPeriod,
			KESKeyHash: orNil(p.KESKeyHash),
		},
		Seq:       p.Seq,
		Signature: bytes.Clone(slot[recSigOff:recSumOff]),
	}
	copy(e.Prev[:], p.Prev)

	// only the canonical encoding of the fields is accepted, so the signed
	// bytes are exactly what was decoded
	if again, err := encMode.Marshal(e.payload()); err != nil || !bytes.Equal(again, enc) {
		return Entry{}, fmt.Errorf("%w: non-canonical payload", ErrCorrupt)
	}

	if _, err := normalize(e.Record); err != nil || len(e.Summary) > MaxSummary {
		return Entry{}, fmt.Errorf("%w: invalid record content", ErrCorrupt)
	}

	e.Hash = linkHash(enc, e.Signature)

	return e, nil
}

// verifyEntry checks e's signature under pub.
func verifyEntry(e Entry, pub ed25519.PublicKey) error {
	enc, err := encMode.Marshal(e.payload())
	if err != nil {
		return fmt.Errorf("signlog: encode entry: %w", err)
	}

	if !ed25519.Verify(pub, signDigest(enc), e.Signature) {
		return fmt.Errorf("%w: entry %d", ErrBadSignature, e.Seq)
	}

	return nil
}

func headerDigest(signed []byte) []byte {
	h := sha256.New()
	h.Write([]byte(headerDomain))
	h.Write(signed)

	return h.Sum(nil)
}

// formatHeader builds the signed header block for a card of n slots.
func formatHeader(id Identity, n uint64) ([]byte, error) {
	pub := id.Public()
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("signlog: invalid identity public key")
	}

	out := make([]byte, BlockSize)
	copy(out, headerMagic)
	binary.BigEndian.PutUint32(out[hdrVersionOff:], FormatVersion)
	binary.BigEndian.PutUint32(out[hdrBlockOff:], BlockSize)
	binary.BigEndian.PutUint32(out[hdrRecBlocksOf:], RecordBlocks)
	binary.BigEndian.PutUint64(out[hdrEntriesOff:], n)

	if _, err := rand.Read(out[hdrCardOff:hdrIdentityOff]); err != nil {
		return nil, err
	}

	copy(out[hdrIdentityOff:], pub)

	sig, err := id.Sign(headerDigest(out[:hdrSignedLen]))
	if err != nil {
		return nil, fmt.Errorf("signlog: sign header: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signlog: identity returned a %d-byte signature", len(sig))
	}

	copy(out[hdrSigOff:], sig)

	return out, nil
}

// parseHeader checks the header block's structure and, when pub is not
// nil, that it names pub; it then checks the signature under the identity
// the header names.
func parseHeader(b []byte, pub ed25519.PublicKey) (Header, error) {
	var h Header

	if string(b[:len(headerMagic)]) != headerMagic {
		return h, fmt.Errorf("%w: header magic", ErrCorrupt)
	}

	h.Version = binary.BigEndian.Uint32(b[hdrVersionOff:])
	if h.Version != FormatVersion {
		return h, fmt.Errorf("%w: format version %d", ErrCorrupt, h.Version)
	}

	h.RecordBlocks = binary.BigEndian.Uint32(b[hdrRecBlocksOf:])
	h.Entries = binary.BigEndian.Uint64(b[hdrEntriesOff:])

	if binary.BigEndian.Uint32(b[hdrBlockOff:]) != BlockSize || h.RecordBlocks != RecordBlocks ||
		binary.BigEndian.Uint32(b[hdrReservedOff:]) != 0 || h.Entries == 0 ||
		h.Entries > (1<<62)/RecordBlocks || !isZero(b[hdrUsedLen:]) {
		return h, fmt.Errorf("%w: header geometry", ErrCorrupt)
	}

	copy(h.CardID[:], b[hdrCardOff:])
	h.Identity = bytes.Clone(b[hdrIdentityOff:hdrSignedLen])
	h.Hash = sha256.Sum256(b)

	if pub != nil && !bytes.Equal(h.Identity, pub) {
		return h, ErrWrongDevice
	}

	if !ed25519.Verify(h.Identity, headerDigest(b[:hdrSignedLen]), b[hdrSigOff:hdrUsedLen]) {
		return h, fmt.Errorf("%w: header", ErrBadSignature)
	}

	return h, nil
}

// slotLBA returns the first block of entry seq's slot.
func slotLBA(seq uint64) uint64 { return 1 + (seq-1)*RecordBlocks }
