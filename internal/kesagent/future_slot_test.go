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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A future slot inside the current KES period must not reach the durable
// guard: with the clock at slot 50, a header for slot 59 is refused, the
// matching slot-52 header still signs, and the guard file reopened after a
// restart records slot 52, not 59.
func TestSignHeaderFutureSlotDoesNotReachTheGuardFile(t *testing.T) {
	a, _, spec := newHeaderAgent(t) // clock at slot 50, period 5 is 50..59
	future := spec
	future.slot = 59
	if _, err := a.SignHeader(5, future.encode(t)); !errors.Is(err, ErrFutureSlot) {
		t.Fatalf("slot 59: want ErrFutureSlot, got %v", err)
	}
	if _, err := a.SignHeader(5, spec.encode(t)); err != nil {
		t.Fatalf("slot 52 after a refused slot 59: %v", err)
	}
	a.Close()
	g, err := NewPeriodGuard(a.profiles[0].cfg.GuardPath)
	if err != nil {
		t.Fatalf("reopen guard: %v", err)
	}
	if slot, ok := lastSignedSlot(g); !ok || slot != 52 {
		t.Fatalf("reopened guard slot = %d %v, want 52 true", slot, ok)
	}
}

func TestNewRefusesANegativeSinglePoolClockSkew(t *testing.T) {
	cold := newColdKey(t)
	_, err := New(Config{
		Mode:              ModeSign,
		SystemStart:       epoch,
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 10,
		MaxClockSkew:      -time.Second,
		ColdVKey:          cold.pub,
		GuardPath:         filepath.Join(t.TempDir(), "guard.json"),
	}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "max_clock_skew") {
		t.Fatalf("err = %v, want a refused max_clock_skew", err)
	}
}
