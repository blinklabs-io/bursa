// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "settings.json")
}

// TestDefaultOffWhenAbsent: a missing settings file yields a usable store whose
// history-expiry defaults to false.
func TestDefaultOffWhenAbsent(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load with no file: %v", err)
	}
	if s.HistoryExpiry() {
		t.Fatal("history expiry should default to false when no file exists")
	}
}

// TestSetPersistsRoundTrip: setting the value writes the file, and a fresh Load
// reads it back — the default-off → on → reload round trip.
func TestSetPersistsRoundTrip(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.SetHistoryExpiry(true); err != nil {
		t.Fatalf("SetHistoryExpiry: %v", err)
	}
	if !s.HistoryExpiry() {
		t.Fatal("in-memory value not updated after SetHistoryExpiry(true)")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("settings file not written: %v", err)
	}

	// A brand new store over the same path must observe the persisted value.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.HistoryExpiry() {
		t.Fatal("persisted history-expiry=true did not survive reload")
	}

	// And turning it back off persists too.
	if err := reloaded.SetHistoryExpiry(false); err != nil {
		t.Fatalf("SetHistoryExpiry(false): %v", err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatalf("reload after off: %v", err)
	}
	if again.HistoryExpiry() {
		t.Fatal("persisted history-expiry=false did not survive reload")
	}
}

// TestSeedDefaultSeedsWhenAbsent: SeedDefault sets the value on first run (no
// persisted value), mirroring BURSA_LEAN seeding the initial default.
func TestSeedDefaultSeedsWhenAbsent(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.SeedDefault(true); err != nil {
		t.Fatalf("SeedDefault: %v", err)
	}
	if !s.HistoryExpiry() {
		t.Fatal("SeedDefault(true) should set the value when none is persisted")
	}
	// It must have hit disk, so a reload sees the seeded value.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.HistoryExpiry() {
		t.Fatal("seeded value did not persist")
	}
}

// TestSeedDefaultDoesNotOverridePersisted: once the user has chosen a value, the
// env seed is ignored — the persisted setting is the source of truth thereafter.
func TestSeedDefaultDoesNotOverridePersisted(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// User explicitly turned it OFF.
	if err := s.SetHistoryExpiry(false); err != nil {
		t.Fatalf("SetHistoryExpiry(false): %v", err)
	}
	// A later seed of true (e.g. BURSA_LEAN=1) must NOT override the user's choice.
	if err := s.SeedDefault(true); err != nil {
		t.Fatalf("SeedDefault: %v", err)
	}
	if s.HistoryExpiry() {
		t.Fatal("SeedDefault must not override a persisted value")
	}

	// Same across a reload + a fresh store's SeedDefault.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := reloaded.SeedDefault(true); err != nil {
		t.Fatalf("reload SeedDefault: %v", err)
	}
	if reloaded.HistoryExpiry() {
		t.Fatal("SeedDefault on reload must not override the persisted false")
	}
}

// TestLoadRejectsCorruptFile: a present-but-corrupt file is a hard error rather
// than silently discarding the user's settings.
func TestLoadRejectsCorruptFile(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load should error on a corrupt settings file")
	}
}

// TestSeedDefaultFalseStillPersistsFirstRun: seeding false on first run records
// an explicit value (so a later env flip to true is correctly ignored). i.e.
// the absence-vs-explicit-false distinction is preserved.
func TestSeedDefaultFalseStillPersistsFirstRun(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.SeedDefault(false); err != nil {
		t.Fatalf("SeedDefault(false): %v", err)
	}
	// Now a different seed must be ignored: the first-run default is locked in.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := reloaded.SeedDefault(true); err != nil {
		t.Fatalf("reload SeedDefault(true): %v", err)
	}
	if reloaded.HistoryExpiry() {
		t.Fatal("first-run SeedDefault(false) should lock in false, not be re-seeded to true")
	}
}
