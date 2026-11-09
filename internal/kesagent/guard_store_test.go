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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/watermark"
	"github.com/blinklabs-io/gouroboros/kes"
)

// pgDSNEnv holds the PostgreSQL connection string for the runtime tests,
// as in the signer watermark tests. Without it they skip.
const pgDSNEnv = "BURSA_TEST_POSTGRES_DSN"

// testPGStore opens a PostgreSQL watermark store, or skips the test when
// BURSA_TEST_POSTGRES_DSN is unset. Each call is a separate connection pool,
// standing in for a separate agent replica.
func testPGStore(t *testing.T) SharedGuardStore {
	t.Helper()
	dsn := os.Getenv(pgDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping PostgreSQL runtime tests", pgDSNEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := watermark.NewPostgresWatermark(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresWatermark: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func openSharedGuard(
	t *testing.T,
	store SharedGuardStore,
	cold coldKeyPair,
	systemStart time.Time,
) *sharedGuard {
	t.Helper()
	g, err := newSharedGuard(store, cold.pub, systemStart)
	if err != nil {
		t.Fatalf("newSharedGuard: %v", err)
	}
	t.Cleanup(g.Close)
	return g
}

// checkSharedGuardSemantics runs the guard rules against two replicas, each
// with its own store handle onto the same records.
func checkSharedGuardSemantics(t *testing.T, storeA, storeB SharedGuardStore) {
	t.Helper()
	cold := newColdKey(t)
	a := openSharedGuard(t, storeA, cold, epoch)
	if !a.Fresh() {
		t.Fatal("first open of an empty store is not fresh")
	}
	if _, set := a.Floor(); set {
		t.Fatal("empty store has a floor")
	}

	if err := a.Authorize("k", 5); err != nil {
		t.Fatalf("Authorize 5: %v", err)
	}
	if err := a.Authorize("k", 5); err != nil {
		t.Fatalf("Authorize 5 again: %v", err)
	}
	if err := a.Authorize("k", 4); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("Authorize 4 after 5: want ErrPeriodRollback, got %v", err)
	}
	if err := a.AuthorizeHeader("k", 5, 52, []byte("A")); err != nil {
		t.Fatalf("header A at 52: %v", err)
	}
	if err := a.AuthorizeHeader("k", 5, 52, []byte("A")); err != nil {
		t.Fatalf("identical retry at 52: %v", err)
	}
	if err := a.AuthorizeHeader(
		"k", 5, 52, []byte("B"),
	); !errors.Is(err, ErrSlotEquivocation) {
		t.Fatalf("header B at 52: want ErrSlotEquivocation, got %v", err)
	}
	if err := a.AuthorizeHeader(
		"k", 5, 51, []byte("C"),
	); !errors.Is(err, ErrSlotRollback) {
		t.Fatalf("slot 51 after 52: want ErrSlotRollback, got %v", err)
	}
	if err := a.AuthorizeHeader(
		"k", 4, 60, []byte("X"),
	); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("period 4 at slot 60: want ErrPeriodRollback, got %v", err)
	}
	if err := a.AuthorizeHeader("k", 6, 53, []byte("D")); err != nil {
		t.Fatalf("header D at 53: %v", err)
	}
	if slot, ok := lastSignedSlot(a); !ok || slot != 53 {
		t.Fatalf("last signed slot = %d %v, want 53 true", slot, ok)
	}

	// A second replica sees the shared floor and slot records.
	b := openSharedGuard(t, storeB, cold, epoch)
	if b.Fresh() {
		t.Fatal("second replica's guard is fresh over existing records")
	}
	if floor, set := b.Floor(); !set || floor != 6 {
		t.Fatalf("second replica floor = %d %v, want 6 true", floor, set)
	}
	if err := b.AuthorizeHeader(
		"k", 6, 53, []byte("E"),
	); !errors.Is(err, ErrSlotEquivocation) {
		t.Fatalf("replica B header E at 53: want ErrSlotEquivocation, got %v", err)
	}
	if err := b.AuthorizeHeader(
		"k", 6, 52, []byte("B"),
	); !errors.Is(err, ErrSlotEquivocation) {
		t.Fatalf("replica B header B at 52: want ErrSlotEquivocation, got %v", err)
	}
	if err := b.AuthorizeHeader("k", 6, 53, []byte("D")); err != nil {
		t.Fatalf("replica B identical retry at 53: %v", err)
	}
	if err := b.Authorize("k", 5); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("replica B Authorize 5: want ErrPeriodRollback, got %v", err)
	}

	// Replica B raises the floor; replica A is refused below it even though
	// its own view of the floor is older, and then reports the new floor.
	if err := b.Authorize("k", 8); err != nil {
		t.Fatalf("replica B Authorize 8: %v", err)
	}
	if err := a.Authorize("k", 7); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("replica A Authorize 7 under shared floor 8: got %v", err)
	}
	if floor, _ := a.Floor(); floor != 8 {
		t.Fatalf("replica A floor after refusal = %d, want 8", floor)
	}

	// The same cold key on another network has its own records: slot
	// numbers overlap across networks.
	other := openSharedGuard(t, storeA, cold, epoch.Add(24*time.Hour))
	if !other.Fresh() {
		t.Fatal("same cold key on another network shares the floor")
	}
	if err := other.AuthorizeHeader("k", 1, 52, []byte("B")); err != nil {
		t.Fatalf("other network header B at 52: %v", err)
	}
}

func TestSharedGuardSemanticsMem(t *testing.T) {
	t.Parallel()
	store := watermark.NewMemWatermark()
	checkSharedGuardSemantics(t, store, store)
}

func TestPostgresGuardSemantics(t *testing.T) {
	t.Parallel()
	checkSharedGuardSemantics(t, testPGStore(t), testPGStore(t))
}

// checkSharedGuardRace has two replicas offer different headers for the same
// slot at the same moment, round after round: exactly one may win each slot
// and the other must be refused as an equivocation.
func checkSharedGuardRace(t *testing.T, storeA, storeB SharedGuardStore) {
	t.Helper()
	cold := newColdKey(t)
	guards := []*sharedGuard{
		openSharedGuard(t, storeA, cold, epoch),
		openSharedGuard(t, storeB, cold, epoch),
	}
	const rounds = 50
	for round := range uint64(rounds) {
		slot := 1000 + round
		start := make(chan struct{})
		errs := make([]error, len(guards))
		var wg sync.WaitGroup
		for i, g := range guards {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				body := fmt.Appendf(nil, "replica-%d-slot-%d", i, slot)
				errs[i] = g.AuthorizeHeader("k", 3, slot, body)
			}()
		}
		close(start)
		wg.Wait()
		wins := 0
		for i, err := range errs {
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrSlotEquivocation):
			default:
				t.Fatalf("round %d replica %d: unexpected error %v", round, i, err)
			}
		}
		if wins != 1 {
			t.Fatalf(
				"slot %d: %d replicas signed (errors %v), want exactly 1",
				slot,
				wins,
				errs,
			)
		}
	}
}

func TestSharedGuardRaceMem(t *testing.T) {
	t.Parallel()
	store := watermark.NewMemWatermark()
	checkSharedGuardRace(t, store, store)
}

func TestPostgresGuardRace(t *testing.T) {
	t.Parallel()
	checkSharedGuardRace(t, testPGStore(t), testPGStore(t))
}

// sharedHeaderAgent is newHeaderAgent with its guard in store and an opcert
// at issue number issue.
func sharedHeaderAgent(
	t *testing.T,
	cold coldKeyPair,
	store SharedGuardStore,
	issue uint64,
) (*Agent, headerSpec) {
	t.Helper()
	cfg := Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		Version:           "test",
		SharedGuard:       store,
	}
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.now = func() time.Time { return atPeriod(5) }
	t.Cleanup(a.Close)
	vkey, err := a.GenStagedKey()
	if err != nil {
		t.Fatalf("GenStagedKey: %v", err)
	}
	opcert := makeOpCert(t, vkey, issue, 3, cold)
	if _, err := a.InstallKey(opcert); err != nil {
		t.Fatalf("InstallKey: %v", err)
	}
	return a, headerSpec{
		slot:      52,
		issuer:    cold.pub,
		hotVkey:   vkey,
		sequence:  issue,
		kesPeriod: 3,
		coldSig:   opCertColdSig(t, opcert),
	}
}

// checkAgentsShareSlotGuard runs two agents for one pool on one network over
// the same store: once one signs a header for a slot, the other refuses a
// different header for it.
func checkAgentsShareSlotGuard(t *testing.T, storeA, storeB SharedGuardStore) {
	t.Helper()
	cold := newColdKey(t)
	a, specA := sharedHeaderAgent(t, cold, storeA, 7)
	b, specB := sharedHeaderAgent(t, cold, storeB, 7)
	if _, err := a.SignHeader(5, specA.encode(t)); err != nil {
		t.Fatalf("agent A SignHeader slot 52: %v", err)
	}
	if _, err := b.SignHeader(5, specB.encode(t)); !errors.Is(
		err,
		ErrSlotEquivocation,
	) {
		t.Fatalf("agent B slot 52: want ErrSlotEquivocation, got %v", err)
	}
	if _, err := a.SignHeader(5, specA.encode(t)); err != nil {
		t.Fatalf("agent A retry of its slot 52 body: %v", err)
	}
	specB.slot = 53
	if _, err := b.SignHeader(5, specB.encode(t)); err != nil {
		t.Fatalf("agent B slot 53: %v", err)
	}
	specA.slot = 53
	if _, err := a.SignHeader(5, specA.encode(t)); !errors.Is(
		err,
		ErrSlotEquivocation,
	) {
		t.Fatalf("agent A slot 53: want ErrSlotEquivocation, got %v", err)
	}
}

func TestAgentsShareSlotGuardMem(t *testing.T) {
	t.Parallel()
	store := watermark.NewMemWatermark()
	checkAgentsShareSlotGuard(t, store, store)
}

func TestPostgresGuardAgentsShareSlotGuard(t *testing.T) {
	t.Parallel()
	checkAgentsShareSlotGuard(t, testPGStore(t), testPGStore(t))
}

func TestNewRefusesGuardPathWithSharedGuard(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Mode:              ModeSign,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		ColdVKey:          newColdKey(t).pub,
		GuardPath:         filepath.Join(t.TempDir(), "guard.json"),
		SharedGuard:       watermark.NewMemWatermark(),
	}
	_, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err == nil || !strings.Contains(err.Error(), "guard_path must be unset") {
		t.Fatalf("New with guard_path and a shared store: got %v", err)
	}
}
