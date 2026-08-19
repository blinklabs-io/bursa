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

//go:build unix

package kesagent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestPeriodGuardKeepsFloorWhenPersistFailsAfterCommit drives the failure that
// happens *after* the guard file has been renamed into place: the floor is
// already durable, so rolling the in-memory floor back would let a later
// Authorize accept a period between the old and new floors and persist it,
// moving the durable floor backwards.
//
// The post-rename failure is produced for real rather than mocked: a directory
// with mode 0300 still permits CreateTemp and Rename (write + execute) but
// refuses the read needed to open and fsync it.
func TestPeriodGuardKeepsFloorWhenPersistFailsAfterCommit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "guard.json")
	g, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	if err := g.Authorize("vkey-old", 10); err != nil {
		t.Fatalf("seed floor: %v", err)
	}

	// Refuse the parent-directory read, so persist fails only after the rename.
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := g.Authorize("vkey-new", 20); err == nil {
		t.Fatal("Authorize: want the post-rename sync failure to surface, got nil")
	}

	// The advanced floor must survive in memory: the guard file already says 20.
	if floor, set := g.Floor(); !set || floor != 20 {
		t.Fatalf("in-memory floor = (%d, %v), want (20, true)", floor, set)
	}
	// The whole point: a period below the committed floor stays refused.
	if err := g.Authorize("vkey-mid", 15); !errors.Is(err, ErrPeriodRollback) {
		t.Fatalf("Authorize(15) after committed floor 20: want ErrPeriodRollback, got %v", err)
	}

	// And the durable state really did advance to 20.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore dir mode: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read guard file: %v", err)
	}
	var st guardState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("unmarshal guard file: %v", err)
	}
	if !st.Set || st.Floor != 20 {
		t.Fatalf("guard file = %+v, want floor 20 set true", st)
	}
}

// TestPeriodGuardRollsBackFloorWhenPersistFailsBeforeCommit is the companion
// case: when the guard file was never written, the in-memory floor must NOT
// advance, or the equal-period fast path would later skip persisting a floor
// that has no durable record.
func TestPeriodGuardRollsBackFloorWhenPersistFailsBeforeCommit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "guard.json")
	g, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	if err := g.Authorize("vkey-old", 10); err != nil {
		t.Fatalf("seed floor: %v", err)
	}

	// A read-only directory fails at CreateTemp, before anything is renamed.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := g.Authorize("vkey-new", 20); err == nil {
		t.Fatal("Authorize: want a persist failure, got nil")
	}
	if floor, set := g.Floor(); !set || floor != 10 {
		t.Fatalf("in-memory floor = (%d, %v), want (10, true) after an uncommitted persist", floor, set)
	}
}

// TestPeriodGuardRetriesPersistAfterUnsyncedCommit covers the interaction
// between the two rules above: a floor whose rename committed but whose
// directory entry was never synced is kept in memory (it must not move
// backwards) yet is not durable, so the equal-period fast path must not skip
// persisting it. Otherwise the gap would go unretried for the rest of the
// period and a crash could still restore the older floor.
func TestPeriodGuardRetriesPersistAfterUnsyncedCommit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "guard.json")
	g, err := NewPeriodGuard(path)
	if err != nil {
		t.Fatalf("NewPeriodGuard: %v", err)
	}
	if err := g.Authorize("vkey-old", 10); err != nil {
		t.Fatalf("seed floor: %v", err)
	}

	// Fail only the post-rename directory read.
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	if err := g.Authorize("vkey-new", 20); err == nil {
		t.Fatal("Authorize: want the post-rename sync failure to surface, got nil")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore dir mode: %v", err)
	}

	// Remove the guard file: if the next equal-period Authorize takes the fast
	// path it will not be recreated, which is exactly the durability gap.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove guard file: %v", err)
	}
	if err := g.Authorize("vkey-new", 20); err != nil {
		t.Fatalf("Authorize(20) retry after an unsynced commit: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("guard file was not rewritten, so the fast path skipped a non-durable floor: %v", err)
	}
	var st guardState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("unmarshal guard file: %v", err)
	}
	if !st.Set || st.Floor != 20 {
		t.Fatalf("guard file = %+v, want floor 20 set true", st)
	}

	// Once durable again, the fast path may resume: a further equal-period call
	// must not rewrite the file.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat guard file: %v", err)
	}
	if err := g.Authorize("vkey-new", 20); err != nil {
		t.Fatalf("Authorize(20) once durable: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat guard file: %v", err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Fatal("equal-period fast path rewrote a floor that was already durable")
	}
}
