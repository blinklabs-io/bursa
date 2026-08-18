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

package kesagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrPeriodRollback is returned when a serve/sign is attempted at a KES period
// below the highest period already served or signed.
var ErrPeriodRollback = errors.New(
	"kesagent: KES period rollback refused (period below monotonic floor)",
)

// PeriodGuard enforces a monotonic non-decreasing floor on the KES period the
// agent will serve or sign for. It protects against re-serving an already
// superseded period after a clock jump, a process restart, or a stale key
// re-install — a belt-and-suspenders complement to KES forward security.
//
// The floor is a single global value (KES periods are absolute, derived from
// the genesis system-start and slot schedule, so they are comparable across
// keys). A period strictly below the floor is refused; a period equal to the
// floor is allowed, because a block producer legitimately signs many block
// headers within a single KES period.
//
// The floor is persisted to a small JSON file with an atomic write
// (temp-file + rename) so it survives restarts. This store is intentionally
// self-contained; it can be migrated onto the shared signer watermark store
// later.
type PeriodGuard struct {
	mu    sync.Mutex
	path  string // empty => in-memory only (non-durable)
	floor uint64
	set   bool
	vkey  string // hex of the active KES vkey at the current floor (informational)
}

type guardState struct {
	Floor uint64 `json:"floor"`
	Set   bool   `json:"set"`
	Vkey  string `json:"kes_vkey,omitempty"`
}

// NewPeriodGuard opens (or creates) a guard backed by the file at path. An
// empty path yields a non-durable in-memory guard (tests / ephemeral use).
func NewPeriodGuard(path string) (*PeriodGuard, error) {
	g := &PeriodGuard{path: path}
	if path == "" {
		return g, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return g, nil
		}
		return nil, fmt.Errorf("kesagent: read guard file %q: %w", path, err)
	}
	if len(data) == 0 {
		return g, nil
	}
	var st guardState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("kesagent: parse guard file %q: %w", path, err)
	}
	g.floor = st.Floor
	g.set = st.Set
	g.vkey = st.Vkey
	return g, nil
}

// Floor returns the current monotonic floor and whether it has been set.
func (g *PeriodGuard) Floor() (uint64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.floor, g.set
}

// Authorize checks that period is not a rollback and, when allowed, advances
// the floor to period. vkeyHex is recorded for diagnostics. It returns
// ErrPeriodRollback if period is below the current floor.
func (g *PeriodGuard) Authorize(vkeyHex string, period uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.set && period < g.floor {
		return fmt.Errorf(
			"%w: period %d < floor %d",
			ErrPeriodRollback,
			period,
			g.floor,
		)
	}
	// Fast path: the floor is unchanged (a producer signs many headers per KES
	// period, so this is the common case). The durable state already records
	// this floor, so skip the temp-file + fsync + rename — ~240x the cost of the
	// KES signature and paid under a.mu on the block-production path. Only the
	// informational vkey is updated in memory. This is safe because g.floor is
	// committed in memory only after a successful persist (see below), so
	// period == g.floor implies it was already durably written.
	if g.set && period == g.floor {
		g.vkey = vkeyHex
		return nil
	}
	// Advancing the floor: persist BEFORE committing the new value in memory, and
	// roll back on failure, so a failed persist leaves the floor unchanged and
	// the next Authorize re-attempts it instead of taking the equal-skip above
	// over a floor that was never durably written.
	prevFloor, prevSet, prevVkey := g.floor, g.set, g.vkey
	g.floor = period
	g.set = true
	g.vkey = vkeyHex
	if err := g.persistLocked(); err != nil {
		g.floor, g.set, g.vkey = prevFloor, prevSet, prevVkey
		return err
	}
	return nil
}

func (g *PeriodGuard) persistLocked() error {
	if g.path == "" {
		return nil
	}
	st := guardState{Floor: g.floor, Set: g.set, Vkey: g.vkey}
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("kesagent: marshal guard state: %w", err)
	}
	dir := filepath.Dir(g.path)
	tmp, err := os.CreateTemp(dir, ".kesguard-*")
	if err != nil {
		return fmt.Errorf("kesagent: create guard temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("kesagent: write guard temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("kesagent: sync guard temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("kesagent: close guard temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("kesagent: chmod guard temp file: %w", err)
	}
	if err := os.Rename(tmpName, g.path); err != nil {
		return fmt.Errorf("kesagent: rename guard file: %w", err)
	}
	// Sync the parent directory too: without this, a crash right after the
	// rename can lose the directory-entry update on some filesystems and
	// restore an earlier (lower) floor on restart -- exactly the rollback
	// this guard exists to prevent.
	if dirFile, err := os.Open(dir); err == nil {
		syncErr := dirFile.Sync()
		closeErr := dirFile.Close()
		if syncErr != nil {
			return fmt.Errorf("kesagent: sync guard dir %q: %w", dir, syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("kesagent: close guard dir %q: %w", dir, closeErr)
		}
	} else {
		return fmt.Errorf("kesagent: open guard dir %q: %w", dir, err)
	}
	return nil
}
