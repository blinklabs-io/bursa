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

// Package signlog is the armory's durable signing log: a hash chain of
// entries, each signed by the device identity key, kept on a block device
// (the microSD card) with the number and hash of the latest entry held in a
// separate head store (the SE050). The writer refuses a card that does not
// match the head, so an older copy, a blank card or a truncated record is
// caught at open and before every append, and the host-side Verify checks
// the whole record against the pinned identity key.
//
// On-medium layout, all integers big-endian:
//
//	block 0                header (one block): magic "BURSALOG", format
//	                       version, block size, record size in blocks, the
//	                       number of record slots, a random card ID, the
//	                       identity public key and the identity signature
//	                       over everything before it; the rest is zero
//	blocks 1 .. 1+N*R      N record slots of R blocks each; slot i holds
//	                       entry i (the first entry is 1)
//
// A record is magic "BSLE", a 16-bit payload length, the deterministic CBOR
// payload, zero padding, the 64-byte identity signature and a SHA-256
// checksum over everything before it. A record written in one piece is
// recognised as torn when its checksum fails. Slots that were never written
// are all zero.
//
// Write ordering: an entry is written to its slot and the medium synced,
// then the head store is advanced, then the caller may release the
// signature. A crash between the medium write and the head update leaves the
// medium one entry ahead of the head; Open accepts that once, if the extra
// entry chains from the head and verifies, and repairs the head. A head ahead
// of the medium, a medium more than one entry ahead, or any hash mismatch
// is refused. The one ambiguity that remains is by design: an entry written
// but whose head update failed was never released, yet stays in the record.
package signlog

import (
	"crypto/ed25519"
	"errors"
)

const (
	// BlockSize is the sector size of the medium.
	BlockSize = 512
	// RecordBlocks is the size of one entry record in blocks.
	RecordBlocks = 4
	// RecordSize is the size of one entry record in bytes.
	RecordSize = BlockSize * RecordBlocks
	// FormatVersion is the on-medium format version.
	FormatVersion = 1
	// DefaultMaxEntries bounds the record slots a freshly formatted medium
	// gets, so a large card does not make every open scan gigabytes.
	DefaultMaxEntries = 1 << 15
	// MaxSummary bounds Record.Summary; longer summaries are cut.
	MaxSummary = 1024
	// HashSize is the size of the chain hash and the body hash.
	HashSize = 32

	// PurposeTxBody and PurposeOpCertNext are the purposes the device signs.
	PurposeTxBody     = "tx-body"
	PurposeOpCertNext = "opcert-next"
)

var (
	// ErrBlank is returned for a blank medium when the head store says
	// entries or a header exist.
	ErrBlank = errors.New("signlog: blank medium but the head store is initialised")
	// ErrCorrupt is returned for a header or record that is malformed or
	// fails its checksum where one was required to be valid.
	ErrCorrupt = errors.New("signlog: corrupt medium")
	// ErrWrongDevice is returned when the medium belongs to another identity.
	ErrWrongDevice = errors.New("signlog: medium belongs to a different device identity")
	// ErrRollback is returned when the medium is behind the head store: an
	// older copy of the card or a truncated record.
	ErrRollback = errors.New("signlog: medium is behind the head store")
	// ErrAhead is returned when the medium is more than one entry ahead of
	// the head store, or one entry ahead without chaining from it.
	ErrAhead = errors.New("signlog: medium is ahead of the head store")
	// ErrHashMismatch is returned when the latest entry's hash differs from
	// the head store's.
	ErrHashMismatch = errors.New("signlog: latest entry does not match the head store")
	// ErrFull is returned when no record slot is left.
	ErrFull = errors.New("signlog: medium is full")
	// ErrBadSignature is returned when an entry or the header signature does
	// not verify.
	ErrBadSignature = errors.New("signlog: bad signature")
	// ErrChain is returned when an entry does not chain from its predecessor.
	ErrChain = errors.New("signlog: broken hash chain")
	// ErrSequence is returned when sequence numbers are not contiguous.
	ErrSequence = errors.New("signlog: sequence numbers are not contiguous")
	// ErrTrailing is returned when data follows the last entry beyond one
	// torn record.
	ErrTrailing = errors.New("signlog: data after the last entry")
	// ErrTornTail is returned by Verify, with the entries before it, when
	// the last record is incomplete.
	ErrTornTail = errors.New("signlog: torn final record")
	// ErrInvalidRecord is returned for a Record Append cannot encode.
	ErrInvalidRecord = errors.New("signlog: invalid record")
	// ErrHeadStore is returned when the head store changed under the writer.
	ErrHeadStore = errors.New("signlog: head store changed")
	// ErrMedium is returned when the medium is too small or unreadable.
	ErrMedium = errors.New("signlog: medium unusable")
)

// Medium is a block device. Reads and writes are whole blocks; len(p) is a
// multiple of BlockSize. WriteBlocks need not be durable until Sync returns.
type Medium interface {
	// NumBlocks returns the size in blocks.
	NumBlocks() uint64
	// ReadBlocks fills p from block lba onward.
	ReadBlocks(lba uint64, p []byte) error
	// WriteBlocks writes p from block lba onward.
	WriteBlocks(lba uint64, p []byte) error
	// Sync flushes written blocks to the medium.
	Sync() error
}

// Head is the number and hash of the latest entry; entry 0 is the header,
// whose hash is the SHA-256 of the header block. The zero Head means the
// head store was never initialised.
type Head struct {
	Seq  uint64
	Hash [HashSize]byte
}

// HeadStore keeps the Head in storage the card cannot reach, such as an
// SE050 binary object. Store must replace the Head atomically.
type HeadStore interface {
	Load() (Head, error)
	Store(Head) error
}

// Identity is the device identity key. Sign signs a message with it; the
// writer signs 32-byte digests, as the other attestations do.
type Identity interface {
	Public() ed25519.PublicKey
	Sign(msg []byte) ([]byte, error)
}

// Record is what the device knows when it signs. A tx-body record carries
// BodyHash; an opcert-next record carries IssueCounter, KESPeriod and
// KESKeyHash, the blake2b-256 of the KES verification key. Summary is the
// parameter summary the policy computed.
type Record struct {
	Profile      string
	Role         string
	Purpose      string
	BodyHash     []byte
	Summary      string
	IssueCounter uint64
	KESPeriod    uint64
	KESKeyHash   []byte
}

// Entry is a Record as logged.
type Entry struct {
	Record
	Seq       uint64
	Prev      [HashSize]byte
	Signature []byte
	// Hash chains the next entry to this one.
	Hash [HashSize]byte
}

// Header identifies the device and the format.
type Header struct {
	Version      uint32
	RecordBlocks uint32
	Entries      uint64
	CardID       [16]byte
	Identity     ed25519.PublicKey
	// Hash is Head.Hash for entry 0.
	Hash [HashSize]byte
}

// Log is a verified record.
type Log struct {
	Header  Header
	Entries []Entry
}

// KeySigner is an Identity backed by an in-memory key.
type KeySigner struct{ key ed25519.PrivateKey }

// NewKeySigner returns an Identity that signs with key.
func NewKeySigner(key ed25519.PrivateKey) *KeySigner { return &KeySigner{key: key} }

// Public implements Identity.
func (k *KeySigner) Public() ed25519.PublicKey {
	return k.key.Public().(ed25519.PublicKey)
}

// Sign implements Identity.
func (k *KeySigner) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(k.key, msg), nil
}
