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
	"errors"
	"sync"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// ErrConflict indicates a different payload was already signed for (key, scope).
var ErrConflict = errors.New("watermark conflict: divergent payload for the same key and scope")

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

func recordKey(key backend.KeyHash, scope string) string { return key.String() + "|" + scope }

func digest(payload []byte) [32]byte { return sha256.Sum256(payload) }

// MemWatermark is an in-memory Watermark. It is non-durable (all records are
// lost on process restart) and grows without bound (one entry per unique
// (key, scope) pair, never evicted). It is suitable for testing and short-lived
// single-process use only.
type MemWatermark struct {
	mu      sync.Mutex
	records map[string][32]byte
}

// NewMemWatermark builds an empty in-memory watermark.
func NewMemWatermark() *MemWatermark { return &MemWatermark{records: map[string][32]byte{}} }

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
