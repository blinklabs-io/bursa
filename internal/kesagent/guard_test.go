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
	// Reopen from disk: the floor must survive.
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
