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

//go:build unix && !aix

package kesagent

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/kes"
)

// TestPeriodGuardLock covers the exclusive lock a guard holds on its file: a
// second open of the same path is refused while the first is open, and
// allowed again once it is closed.
func TestPeriodGuardLock(t *testing.T) {
	for _, tc := range []struct {
		name       string
		closeFirst bool
		wantErr    error
	}{
		{name: "held", closeFirst: false, wantErr: ErrGuardLocked},
		{name: "released", closeFirst: true, wantErr: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "guard.json")
			g, err := NewPeriodGuard(path)
			if err != nil {
				t.Fatalf("NewPeriodGuard: %v", err)
			}
			t.Cleanup(g.Close)
			// A signed slot makes the guard file itself be replaced by a
			// rename, which must not drop the lock.
			if err := g.AuthorizeHeader("vk", 5, 100, []byte("a")); err != nil {
				t.Fatalf("AuthorizeHeader: %v", err)
			}
			if tc.closeFirst {
				g.Close()
			}
			g2, err := NewPeriodGuard(path)
			if g2 != nil {
				t.Cleanup(g2.Close)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("reopen: %v", err)
				}
				if slot, ok := g2.LastSignedSlot(); !ok || slot != 100 {
					t.Fatalf("reloaded slot = %d %v, want 100 true", slot, ok)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("reopen: want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestPeriodGuardCloseIsIdempotent closes a guard twice, and an in-memory
// guard and a nil guard once, without panicking.
func TestPeriodGuardCloseIsIdempotent(t *testing.T) {
	g, err := NewPeriodGuard(filepath.Join(t.TempDir(), "guard.json"))
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	g.Close()
	g.Close()
	mem, err := NewPeriodGuard("")
	if err != nil {
		t.Fatalf("NewPeriodGuard in memory: %v", err)
	}
	mem.Close()
	var none *PeriodGuard
	none.Close()
}

// TestNewRefusesAGuardFileHeldByAnotherAgent starts a second agent on the
// guard file of a running one: it must fail until the first one closes.
func TestNewRefusesAGuardFileHeldByAnotherAgent(t *testing.T) {
	cold := newColdKey(t)
	cfg := Config{
		Mode:              ModeSign,
		Depth:             kes.CardanoKesDepth,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  62,
		ColdVKey:          cold.pub,
		EvolveInterval:    time.Hour,
		GuardPath:         filepath.Join(t.TempDir(), "guard.json"),
		Version:           "test",
	}
	first, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(first.Close)
	if second, err := New(cfg, nil, nil); !errors.Is(err, ErrGuardLocked) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second agent: want ErrGuardLocked, got %v", err)
	}
	first.Close()
	again, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New after the first agent closed: %v", err)
	}
	again.Close()
}
