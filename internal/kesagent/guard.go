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
	"crypto/sha256"
	"encoding/hex"
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

// ErrSlotRollback is returned when a header is presented for a slot below the
// last slot the agent signed a header for. A producer that asks for an older
// slot is behind the chain the pool already extended.
var ErrSlotRollback = errors.New(
	"kesagent: header slot below the last signed slot refused",
)

// ErrSlotEquivocation is returned when a header body differs from the one the
// agent already signed for the same slot. Signing it would publish a second
// block for the pool in that slot.
var ErrSlotEquivocation = errors.New(
	"kesagent: a different header was already signed for this slot",
)

// ErrGuardLocked is returned when another agent process holds the lock on a
// guard file. Two processes on one guard file would each keep their own slot
// record and could each sign a header for the same slot.
var ErrGuardLocked = errors.New("kesagent: guard file is locked")

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
//
// A durable guard holds an exclusive lock on a sidecar file (the guard path
// plus ".lock") from NewPeriodGuard until Close, so a second agent process on
// the same guard file fails to start. The sidecar, not the guard file, is
// locked because every write replaces the guard file by a rename.
type PeriodGuard struct {
	mu    sync.Mutex
	path  string // empty => in-memory only (non-durable)
	floor uint64
	set   bool
	// durable is false when floor reached the guard file but its directory
	// entry was not synced, so the value can still be lost by a crash. The
	// equal-period fast path must not skip persisting while it is false.
	durable bool
	vkey    string // hex of the active KES vkey at the current floor (informational)
	// slot and header record the last block header signed for the pool: its
	// absolute slot and the SHA-256 of its body. They are persisted with the
	// floor so a restart or a key install cannot sign a second header for a
	// signed slot.
	slot    uint64
	slotSet bool
	header  string
	// lock is the held lock on the sidecar file; nil in memory or off unix.
	lock *os.File
	// fresh is true when the guard file was missing or empty when opened, so
	// no signed slot was known at startup.
	fresh bool
}

type guardState struct {
	Floor uint64 `json:"floor"`
	Set   bool   `json:"set"`
	Vkey  string `json:"kes_vkey,omitempty"`
	// Slot, SlotSet and Header are absent from guard files written before the
	// slot guard; such a file loads with no signed slot.
	Slot    uint64 `json:"last_signed_slot,omitempty"`
	SlotSet bool   `json:"last_signed_slot_set,omitempty"`
	Header  string `json:"last_signed_header_sha256,omitempty"`
}

// NewPeriodGuard opens (or creates) a guard backed by the file at path and
// locks it until Close; it returns ErrGuardLocked when another process holds
// the lock. Direct guard tests may use an empty path for an in-memory
// instance; Agent.New requires a durable path.
func NewPeriodGuard(path string) (*PeriodGuard, error) {
	// durable starts true: an in-memory guard has nothing to persist, an absent
	// or empty file has no floor to lose, and a floor read back from the file was
	// written and synced by a previous run.
	g := &PeriodGuard{path: path, durable: true}
	if path == "" {
		return g, nil
	}
	// Lock before reading, so the record loaded is the one this process
	// alone will advance.
	lock, err := lockGuardFile(path + ".lock")
	if err != nil {
		return nil, err
	}
	g.lock = lock
	if err := g.load(); err != nil {
		g.Close()
		return nil, err
	}
	return g, nil
}

// load reads the guard file into g. A missing or empty file leaves g empty
// and marks it fresh.
func (g *PeriodGuard) load() error {
	data, err := os.ReadFile(g.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			g.fresh = true
			return nil
		}
		return fmt.Errorf("kesagent: read guard file %q: %w", g.path, err)
	}
	if len(data) == 0 {
		g.fresh = true
		return nil
	}
	var st guardState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("kesagent: parse guard file %q: %w", g.path, err)
	}
	g.floor = st.Floor
	g.set = st.Set
	g.vkey = st.Vkey
	g.slot = st.Slot
	g.slotSet = st.SlotSet
	g.header = st.Header
	return nil
}

// Fresh reports whether the guard file was missing or empty when the guard
// was opened. That is expected on a first start; on any later start it means
// the record of the last signed slot was lost.
func (g *PeriodGuard) Fresh() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fresh
}

// Close releases the guard file lock. It is safe to call more than once and
// on a nil guard. The lock file is left in place: removing it would let a
// process that opened the old file and one that creates a new one both hold
// a lock.
func (g *PeriodGuard) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lock != nil {
		_ = g.lock.Close()
		g.lock = nil
	}
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
	// informational vkey is updated in memory.
	//
	// It requires g.durable, not just g.set: a floor whose rename committed but
	// whose directory entry was never synced can still be lost by a crash, so
	// skipping the write here would leave that gap unretried for the rest of the
	// period. In that state fall through and persist again.
	if g.set && g.durable && period == g.floor {
		g.vkey = vkeyHex
		return nil
	}
	// Advancing the floor: persist BEFORE committing the new value in memory, and
	// roll back on failure, so a failed persist leaves the floor unchanged and
	// the next Authorize re-attempts it instead of taking the equal-skip above
	// over a floor that was never durably written.
	//
	// Rolling back is only correct while the new floor has NOT reached disk. Once
	// the rename commits, the guard file holds the higher floor; restoring the
	// lower one in memory would let a later Authorize accept a period between the
	// old and new floors and persist it, moving the durable floor backwards --
	// precisely the rollback this guard exists to prevent. So a post-commit
	// failure (a directory sync that could not be completed) keeps the new floor
	// in memory and surfaces the error.
	prevFloor, prevSet, prevVkey := g.floor, g.set, g.vkey
	prevDurable := g.durable
	g.floor = period
	g.set = true
	g.vkey = vkeyHex
	g.durable = false
	committed, err := g.persistLocked()
	if err != nil {
		if !committed {
			g.floor, g.set, g.vkey = prevFloor, prevSet, prevVkey
			g.durable = prevDurable
		}
		// A committed-but-unsynced floor stays in memory (it must never move
		// backwards) but remains non-durable, so the next Authorize retries.
		return err
	}
	g.durable = true
	return nil
}

// LastSignedSlot returns the slot of the last header signed and whether one
// has been signed.
func (g *PeriodGuard) LastSignedSlot() (uint64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.slot, g.slotSet
}

// AuthorizeHeader is Authorize for a block header body at an absolute slot.
// Besides the period floor it allows one header body per slot and never an
// older slot: a slot above the last signed one is recorded durably before it
// returns; the same slot is allowed again only for the identical body, so a
// producer can retry after a lost reply; a different body for that slot
// returns ErrSlotEquivocation and a lower slot returns ErrSlotRollback.
func (g *PeriodGuard) AuthorizeHeader(
	vkeyHex string,
	period uint64,
	slot uint64,
	headerBody []byte,
) error {
	sum := sha256.Sum256(headerBody)
	header := hex.EncodeToString(sum[:])
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
	if g.slotSet {
		switch {
		case slot < g.slot:
			return fmt.Errorf(
				"%w: slot %d < last signed slot %d",
				ErrSlotRollback,
				slot,
				g.slot,
			)
		case slot == g.slot && header != g.header:
			return fmt.Errorf("%w: slot %d", ErrSlotEquivocation, slot)
		case slot == g.slot && g.durable:
			// The identical header again: already recorded durably.
			g.vkey = vkeyHex
			return nil
		}
	}
	// Record the new slot, or retry persisting a slot whose record is not yet
	// durable. As in Authorize, roll back only when the write did not reach
	// the guard file.
	prevFloor, prevSet, prevVkey := g.floor, g.set, g.vkey
	prevSlot, prevSlotSet, prevHeader := g.slot, g.slotSet, g.header
	prevDurable := g.durable
	if !g.set || period > g.floor {
		g.floor = period
	}
	g.set = true
	g.vkey = vkeyHex
	g.slot = slot
	g.slotSet = true
	g.header = header
	g.durable = false
	committed, err := g.persistLocked()
	if err != nil {
		if !committed {
			g.floor, g.set, g.vkey = prevFloor, prevSet, prevVkey
			g.slot, g.slotSet, g.header = prevSlot, prevSlotSet, prevHeader
			g.durable = prevDurable
		}
		return err
	}
	g.durable = true
	return nil
}

// persistLocked writes the guard state durably. It reports whether the new
// state reached the guard file: once the rename commits, the on-disk floor has
// advanced even if a later step (the parent-directory sync) fails, and the
// caller must not roll its in-memory floor back below it.
func (g *PeriodGuard) persistLocked() (committed bool, err error) {
	if g.path == "" {
		return true, nil
	}
	st := guardState{
		Floor:   g.floor,
		Set:     g.set,
		Vkey:    g.vkey,
		Slot:    g.slot,
		SlotSet: g.slotSet,
		Header:  g.header,
	}
	data, err := json.Marshal(st)
	if err != nil {
		return false, fmt.Errorf("kesagent: marshal guard state: %w", err)
	}
	dir := filepath.Dir(g.path)
	tmp, err := os.CreateTemp(dir, ".kesguard-*")
	if err != nil {
		return false, fmt.Errorf("kesagent: create guard temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("kesagent: write guard temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("kesagent: sync guard temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("kesagent: close guard temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return false, fmt.Errorf("kesagent: chmod guard temp file: %w", err)
	}
	if err := os.Rename(tmpName, g.path); err != nil {
		return false, fmt.Errorf("kesagent: rename guard file: %w", err)
	}
	// Sync the parent directory too: without this, a crash right after the
	// rename can lose the directory-entry update on some filesystems and
	// restore an earlier (lower) floor on restart -- exactly the rollback
	// this guard exists to prevent.
	if err := syncDirectory(dir); err != nil {
		return true, fmt.Errorf("kesagent: sync guard dir %q: %w", dir, err)
	}
	return true, nil
}
