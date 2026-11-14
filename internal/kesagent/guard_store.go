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
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

// slotGuard is a profile's period floor and slot record. PeriodGuard keeps
// them in a local file; sharedGuard keeps them in a watermark store that
// several agent replicas use together.
type slotGuard interface {
	// Fresh reports whether the guard had no record when it was opened.
	Fresh() bool
	// Floor returns the KES period floor and whether one is set.
	Floor() (uint64, bool)
	// Authorize refuses a period below the floor and raises the floor to it.
	Authorize(vkeyHex string, period uint64) error
	// AuthorizeHeader is Authorize for a header body at an absolute slot.
	AuthorizeHeader(vkeyHex string, period, slot uint64, headerBody []byte) error
	// Close releases what the guard holds.
	Close()
}

var (
	_ slotGuard = (*PeriodGuard)(nil)
	_ slotGuard = (*sharedGuard)(nil)
)

// SharedGuardStore is a watermark store that several agent replicas share,
// such as watermark.PostgresWatermark. With one configured, every profile's
// period floor and slot records live in it instead of a guard file.
type SharedGuardStore interface {
	watermark.Watermark
	watermark.CounterWatermark
}

// sharedGuardTimeout bounds each store call. Calls are made under the
// profile lock on the signing path, so a hung database must not hold it.
const sharedGuardTimeout = 5 * time.Second

// sharedGuard is a profile's guard in a SharedGuardStore. The record key is
// the hash of the pool's cold verification key; scopes carry the profile's
// network (its genesis system start), because one cold key may serve several
// networks whose slot numbers overlap.
//
//   - The period floor is one non-decreasing counter, raised with
//     CheckAndRaiseFloor: a period below it is refused on every replica.
//   - Each signed slot is one payload record, written with CheckAndCommit,
//     or together with the floor in one write when the store implements
//     watermark.FloorCommitWatermark:
//     the first header body recorded for a slot wins on every replica, an
//     identical body passes again (a retry), and a different body is refused
//     as ErrSlotEquivocation.
//   - Refusing a slot older than the last one signed is per replica: the
//     replica's own last signed slot, held in memory, as an extra check.
type sharedGuard struct {
	store      SharedGuardStore
	key        backend.KeyHash
	floorScope string
	slotPrefix string

	mu      sync.Mutex
	floor   uint64
	set     bool
	slot    uint64
	slotSet bool
	fresh   bool
}

// newSharedGuard opens the guard of the profile for coldVKey on the network
// that starts at systemStart, loading the shared period floor.
func newSharedGuard(
	store SharedGuardStore,
	coldVKey []byte,
	systemStart time.Time,
) (*sharedGuard, error) {
	network := systemStart.UTC().Format(time.RFC3339Nano)
	g := &sharedGuard{
		store:      store,
		key:        backend.HashPublicKey(coldVKey),
		floorScope: "kes-agent:" + network + ":kes-period-floor",
		slotPrefix: "kes-agent:" + network + ":slot:",
	}
	ctx, cancel := context.WithTimeout(context.Background(), sharedGuardTimeout)
	defer cancel()
	floor, set, err := store.CounterFor(ctx, g.key, g.floorScope)
	if err != nil {
		return nil, fmt.Errorf("kesagent: read shared period floor: %w", err)
	}
	g.floor, g.set, g.fresh = floor, set, !set
	return g, nil
}

// Fresh reports whether the store had no period floor for the profile when
// the guard was opened.
func (g *sharedGuard) Fresh() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fresh
}

// Floor returns the period floor as this replica last saw it in the store.
// Another replica may have raised it since; every Authorize checks the store.
func (g *sharedGuard) Floor() (uint64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.floor, g.set
}

// Close does nothing: the store belongs to the caller that configured it.
func (g *sharedGuard) Close() {}

// Authorize raises the shared period floor to period, or returns
// ErrPeriodRollback when the floor is already above it.
func (g *sharedGuard) Authorize(_ string, period uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), sharedGuardTimeout)
	defer cancel()
	return g.raiseFloorLocked(ctx, period)
}

// AuthorizeHeader raises the shared period floor to period and records
// headerBody as the one header signed for slot. It refuses a period below the
// floor (ErrPeriodRollback), a slot below this replica's last signed slot
// (ErrSlotRollback) and a body that differs from the one any replica recorded
// for slot (ErrSlotEquivocation).
func (g *sharedGuard) AuthorizeHeader(
	_ string,
	period uint64,
	slot uint64,
	headerBody []byte,
) error {
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
	if g.slotSet && slot < g.slot {
		return fmt.Errorf(
			"%w: slot %d < last signed slot %d",
			ErrSlotRollback,
			slot,
			g.slot,
		)
	}
	ctx, cancel := context.WithTimeout(context.Background(), sharedGuardTimeout)
	defer cancel()
	scope := g.slotPrefix + strconv.FormatUint(slot, 10)
	var err error
	if fc, ok := g.store.(watermark.FloorCommitWatermark); ok {
		// One store write raises the floor and records the slot.
		err = fc.CheckAndRaiseFloorAndCommit(
			ctx, g.key, g.floorScope, period, scope, headerBody,
		)
		if errors.Is(err, watermark.ErrCounterRegression) {
			return g.floorRefusedLocked(ctx, period)
		}
		if err == nil || errors.Is(err, watermark.ErrConflict) {
			g.raiseLocalFloorLocked(period)
		}
	} else {
		if err := g.raiseFloorLocked(ctx, period); err != nil {
			return err
		}
		err = g.store.CheckAndCommit(ctx, g.key, scope, headerBody)
	}
	if errors.Is(err, watermark.ErrConflict) {
		return fmt.Errorf("%w: slot %d", ErrSlotEquivocation, slot)
	}
	if err != nil {
		return fmt.Errorf("kesagent: record slot %d in shared guard: %w", slot, err)
	}
	if !g.slotSet || slot > g.slot {
		g.slot, g.slotSet = slot, true
	}
	return nil
}

// raiseFloorLocked raises the shared floor to period. On a refusal it reloads
// the floor so Floor reports the value that refused it. Caller holds g.mu.
func (g *sharedGuard) raiseFloorLocked(ctx context.Context, period uint64) error {
	err := g.store.CheckAndRaiseFloor(ctx, g.key, g.floorScope, period)
	if errors.Is(err, watermark.ErrCounterRegression) {
		return g.floorRefusedLocked(ctx, period)
	}
	if err != nil {
		return fmt.Errorf("kesagent: raise shared period floor: %w", err)
	}
	g.raiseLocalFloorLocked(period)
	return nil
}

// floorRefusedLocked reloads the shared floor after the store refused period,
// so Floor reports the value that refused it, and returns ErrPeriodRollback.
// Caller holds g.mu.
func (g *sharedGuard) floorRefusedLocked(ctx context.Context, period uint64) error {
	floor, set, rerr := g.store.CounterFor(ctx, g.key, g.floorScope)
	if rerr == nil && set && (!g.set || floor > g.floor) {
		g.floor, g.set = floor, true
	}
	if rerr == nil && set {
		return fmt.Errorf(
			"%w: period %d < floor %d",
			ErrPeriodRollback,
			period,
			floor,
		)
	}
	return fmt.Errorf("%w: period %d", ErrPeriodRollback, period)
}

// raiseLocalFloorLocked records that the store accepted period as the floor.
// Caller holds g.mu.
func (g *sharedGuard) raiseLocalFloorLocked(period uint64) {
	if !g.set || period > g.floor {
		g.floor, g.set = period, true
	}
}
