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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPeriodGuardMonotonic(t *testing.T) {
	g, err := NewPeriodGuard("")
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	if err := g.Authorize("vk", 5); err != nil {
		t.Fatalf("authorize 5: %v", err)
	}
	// Equal period is allowed (a producer signs many blocks in one KES period).
	if err := g.Authorize("vk", 5); err != nil {
		t.Fatalf("authorize 5 again: %v", err)
	}
	// A lower period is a rollback and must be refused.
	if err := g.Authorize("vk", 4); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("authorize 4: want ErrPeriodRollback, got %v", err)
	}
	// Advancing is allowed.
	if err := g.Authorize("vk", 6); err != nil {
		t.Fatalf("authorize 6: %v", err)
	}
	floor, set := g.Floor()
	if !set || floor != 6 {
		t.Fatalf("floor = %d set=%v, want 6 true", floor, set)
	}
}

func TestPeriodGuardDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.json")
	g, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	if err := g.Authorize("vk", 42); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	// Reopen from disk: the floor must survive. Close first, as a restart
	// does, to release the guard file lock.
	g.Close()
	g2, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	floor, set := g2.Floor()
	if !set || floor != 42 {
		t.Fatalf("reloaded floor = %d set=%v, want 42 true", floor, set)
	}
	if err := g2.Authorize("vk", 41); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("rollback after reload: want ErrPeriodRollback, got %v", err)
	}
}

func TestPeriodGuardHeaderSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.json")
	g, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	a, b := []byte("header a"), []byte("header b")
	if err := g.AuthorizeHeader("vk", 5, 100, a); err != nil {
		t.Fatalf("slot 100: %v", err)
	}
	if err := g.AuthorizeHeader("vk", 5, 100, a); err != nil {
		t.Fatalf("slot 100, same body: %v", err)
	}
	if err := g.AuthorizeHeader("vk", 5, 100, b); !errors.Is(
		err,
		ErrSlotEquivocation,
	) {
		t.Fatalf("slot 100, other body: want ErrSlotEquivocation, got %v", err)
	}
	if err := g.AuthorizeHeader("vk", 5, 99, b); !errors.Is(
		err,
		ErrSlotRollback,
	) {
		t.Fatalf("slot 99: want ErrSlotRollback, got %v", err)
	}
	// The period floor still applies to headers.
	if err := g.AuthorizeHeader("vk", 4, 101, b); !errors.Is(
		err,
		ErrPeriodRollback,
	) {
		t.Fatalf("period 4: want ErrPeriodRollback, got %v", err)
	}
	if err := g.AuthorizeHeader("vk2", 6, 130, b); err != nil {
		t.Fatalf("slot 130, period 6: %v", err)
	}
	if floor, set := g.Floor(); !set || floor != 6 {
		t.Fatalf("floor = %d %v, want 6 true", floor, set)
	}

	// The record survives a restart, and a new key changes nothing.
	g.Close()
	g2, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if slot, ok := lastSignedSlot(g2); !ok || slot != 130 {
		t.Fatalf("reloaded slot = %d %v, want 130 true", slot, ok)
	}
	if err := g2.AuthorizeHeader("vk3", 6, 130, a); !errors.Is(
		err,
		ErrSlotEquivocation,
	) {
		t.Fatalf("after reload, other body: want ErrSlotEquivocation, got %v", err)
	}
	if err := g2.AuthorizeHeader("vk3", 6, 130, b); err != nil {
		t.Fatalf("after reload, same body: %v", err)
	}
	if err := g2.AuthorizeHeader("vk3", 6, 129, b); !errors.Is(
		err,
		ErrSlotRollback,
	) {
		t.Fatalf("after reload, slot 129: want ErrSlotRollback, got %v", err)
	}
}

func TestPeriodGuardLoadsFileWithoutSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.json")
	if err := os.WriteFile(
		path,
		[]byte(`{"floor":7,"set":true,"kes_vkey":"aa"}`),
		0o600,
	); err != nil {
		t.Fatalf("write old guard file: %v", err)
	}
	g, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	if _, ok := lastSignedSlot(g); ok {
		t.Fatal("old guard file loaded a signed slot")
	}
	if err := g.AuthorizeHeader("vk", 7, 1, []byte("h")); err != nil {
		t.Fatalf("first header after upgrade: %v", err)
	}
	if err := g.AuthorizeHeader("vk", 6, 2, []byte("h2")); !errors.Is(
		err,
		ErrPeriodRollback,
	) {
		t.Fatalf("floor kept across upgrade: want ErrPeriodRollback, got %v", err)
	}
}

// TestPeriodGuardHeaderRetryAtHigherPeriodRaisesFloor verifies that the
// identical header for a recorded slot, presented at a period above the
// floor, raises the floor instead of returning before persisting.
func TestPeriodGuardHeaderRetryAtHigherPeriodRaisesFloor(t *testing.T) {
	g, err := NewPeriodGuard(filepath.Join(t.TempDir(), "guard.json"))
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	body := []byte("header")
	if err := g.AuthorizeHeader("aa", 1, 10, body); err != nil {
		t.Fatalf("AuthorizeHeader period 1: %v", err)
	}
	if err := g.AuthorizeHeader("aa", 2, 10, body); err != nil {
		t.Fatalf("AuthorizeHeader period 2: %v", err)
	}
	if err := g.Authorize("aa", 1); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("Authorize period 1 after the floor rose: got %v, want ErrPeriodRollback", err)
	}
}

// lastSignedSlot reads g's slot record for assertions.
func lastSignedSlot(g slotGuard) (uint64, bool) {
	switch g := g.(type) {
	case *PeriodGuard:
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.slot, g.slotSet
	case *sharedGuard:
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.slot, g.slotSet
	default:
		panic(fmt.Sprintf("lastSignedSlot: unexpected guard %T", g))
	}
}
