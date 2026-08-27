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

package watermark

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// ErrConflict indicates a different payload was already signed for (key, scope).
var ErrConflict = errors.New("watermark conflict: divergent payload for the same key and scope")

// ErrCounterRegression indicates a monotonic counter was not strictly greater
// than the highest already recorded for (key, scope). It is the anti-double-sign
// guard for operational-certificate issue counters.
var ErrCounterRegression = errors.New("watermark conflict: counter is not strictly greater than the highest already signed")

const (
	readinessProbeRecordKey   = "__bursa_readiness_probe__"
	readinessProbePayloadHash = "0000000000000000000000000000000000000000000000000000000000000000"
	readinessProbeCounter     = "0000000000000000"
)

// Mode controls how the coordinator applies the watermark.
type Mode string

const (
	ModeOff     Mode = "off"
	ModeWarn    Mode = "warn"
	ModeEnforce Mode = "enforce"
)

// Watermark records and guards signed payloads.
type Watermark interface {
	// Check returns ErrConflict if a different payload was recorded for (key, scope).
	Check(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error
	// CheckAndCommit atomically checks for a divergent payload and records this
	// payload when no record exists. Enforce-mode callers must use this instead
	// of a separate Check followed by Commit.
	CheckAndCommit(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error
	// Commit records that payload was signed for (key, scope).
	// Implementations must be first-writer-wins: a second Commit for the same
	// (key, scope) with a different payload silently keeps the original record.
	Commit(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error
}

// CounterWatermark guards a strictly-increasing per-(key, scope) counter, such
// as an operational-certificate issue counter. It is a distinct guard from the
// divergent-payload Watermark: here the invariant is monotonicity (each recorded
// value must exceed the previous), not payload equality. The Mem, Sqlite and
// Postgres stores implement both interfaces on the same backing store.
type CounterWatermark interface {
	// CounterFor returns the highest counter recorded for (key, scope) and
	// whether any record exists. It performs no mutation.
	CounterFor(ctx context.Context, key backend.KeyHash, scope string) (uint64, bool, error)
	// CheckAndCommitCounter atomically records counter as the new highest for
	// (key, scope) if and only if it is strictly greater than the highest already
	// recorded (or none exists). It returns ErrCounterRegression, recording
	// nothing, when counter is not strictly greater. The check and commit are a
	// single atomic operation so that two concurrent callers with the same
	// counter cannot both succeed.
	CheckAndCommitCounter(ctx context.Context, key backend.KeyHash, scope string, counter uint64) error
}

// Pinger is an optional interface a Watermark store implements when it has a
// remote or file dependency whose writeability the readiness probe can verify.
// Stores without an external dependency (e.g. MemWatermark) need not implement
// it; the readiness probe treats their absence as always-ready.
type Pinger interface {
	// Ping verifies the store's backing dependency accepts required writes.
	Ping(ctx context.Context) error
}

// counterEncode renders a uint64 as a fixed-width, big-endian hex string so that
// lexicographic string comparison (used by the sqlite and postgres stores)
// matches numeric comparison, and no lossy uint64->int64 conversion is needed.
func counterEncode(counter uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter)
	return hex.EncodeToString(b[:])
}

// counterDecode reverses counterEncode, rejecting any value that is not exactly
// 8 hex-encoded bytes.
func counterDecode(s string) (uint64, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 8 {
		return 0, errors.New("corrupt stored counter")
	}
	return binary.BigEndian.Uint64(raw), nil
}

// Compile-time proof the in-process and sqlite stores satisfy both guards.
var (
	_ Watermark        = (*MemWatermark)(nil)
	_ CounterWatermark = (*MemWatermark)(nil)
	_ Watermark        = (*SqliteWatermark)(nil)
	_ CounterWatermark = (*SqliteWatermark)(nil)
	_ Pinger           = (*SqliteWatermark)(nil)
)

func recordKey(key backend.KeyHash, scope string) string { return key.String() + "|" + scope }

func digest(payload []byte) [32]byte { return sha256.Sum256(payload) }

// MemWatermark is an in-memory Watermark. It is non-durable (all records are
// lost on process restart) and grows without bound (one entry per unique
// (key, scope) pair, never evicted). It is suitable for testing and short-lived
// single-process use only.
type MemWatermark struct {
	mu       sync.Mutex
	records  map[string][32]byte
	counters map[string]uint64
}

// NewMemWatermark builds an empty in-memory watermark.
func NewMemWatermark() *MemWatermark {
	return &MemWatermark{records: map[string][32]byte{}, counters: map[string]uint64{}}
}

func (m *MemWatermark) Check(_ context.Context, key backend.KeyHash, scope string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.records[recordKey(key, scope)]; ok && prev != digest(payload) {
		return ErrConflict
	}
	return nil
}

func (m *MemWatermark) CheckAndCommit(_ context.Context, key backend.KeyHash, scope string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := recordKey(key, scope)
	d := digest(payload)
	if prev, ok := m.records[k]; ok {
		if prev != d {
			return ErrConflict
		}
		return nil
	}
	m.records[k] = d
	return nil
}

func (m *MemWatermark) Commit(_ context.Context, key backend.KeyHash, scope string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := recordKey(key, scope)
	if _, ok := m.records[k]; !ok {
		m.records[k] = digest(payload)
	}
	return nil
}

func (m *MemWatermark) CounterFor(_ context.Context, key backend.KeyHash, scope string) (uint64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.counters[recordKey(key, scope)]
	return v, ok, nil
}

func (m *MemWatermark) CheckAndCommitCounter(_ context.Context, key backend.KeyHash, scope string, counter uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := recordKey(key, scope)
	if prev, ok := m.counters[k]; ok && counter <= prev {
		return ErrCounterRegression
	}
	m.counters[k] = counter
	return nil
}
