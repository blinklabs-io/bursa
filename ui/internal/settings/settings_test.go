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
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadRejectsOversizedFile(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, make([]byte, maxSettingsLen+1), 0o600); err != nil {
		t.Fatalf("seed oversized file: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load should reject an oversized settings file")
	}
	if !strings.Contains(err.Error(), "settings file exceeds") {
		t.Fatalf("Load error = %q, want size-cap error", err)
	}
}

func TestSetHistoryExpiryRollsBackOnPersistError(t *testing.T) {
	enabled := true
	s := &Store{
		path: filepath.Join(t.TempDir(), "missing-parent", "settings.json"),
		d: data{
			Version:       settingsVersion,
			HistoryExpiry: &enabled,
		},
	}

	if err := s.SetHistoryExpiry(false); err == nil {
		t.Fatal("SetHistoryExpiry should fail when the settings directory is missing")
	}
	if !s.HistoryExpiry() {
		t.Fatal("failed SetHistoryExpiry must leave the in-memory setting unchanged")
	}
}

func TestSetHistoryExpiryDoesNotRollBackAfterRename(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	origSyncDir := syncDir
	syncDir = func(string) error {
		return errors.New("sync failed")
	}
	t.Cleanup(func() {
		syncDir = origSyncDir
	})

	err = s.SetHistoryExpiry(true)
	if err == nil {
		t.Fatal("SetHistoryExpiry should return the syncDir error")
	}
	if !strings.Contains(err.Error(), "sync settings dir") {
		t.Fatalf("SetHistoryExpiry error = %q, want syncDir error", err)
	}
	if !s.HistoryExpiry() {
		t.Fatal("post-rename syncDir failure must keep memory aligned with replaced settings file")
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.HistoryExpiry() {
		t.Fatal("post-rename syncDir failure should leave the replaced settings file readable")
	}
}

// TestAutoLockDefaultsWhenAbsent: a missing settings file yields the
// documented default timeout (15 minutes), not "Off".
func TestAutoLockDefaultsWhenAbsent(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load with no file: %v", err)
	}
	if got := s.AutoLockMinutes(); got != defaultAutoLockMinutes {
		t.Fatalf("AutoLockMinutes() = %d, want default %d", got, defaultAutoLockMinutes)
	}
}

// TestAutoLockSetPersistsRoundTrip: setting the value writes the file, and a
// fresh Load reads it back — including "Off" (0), which must survive the
// round trip distinctly from "never persisted" (which also reads back as a
// non-zero default, so this specifically exercises the persisted-zero path).
func TestAutoLockSetPersistsRoundTrip(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.SetAutoLockMinutes(5); err != nil {
		t.Fatalf("SetAutoLockMinutes(5): %v", err)
	}
	if got := s.AutoLockMinutes(); got != 5 {
		t.Fatalf("in-memory AutoLockMinutes() = %d, want 5", got)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.AutoLockMinutes(); got != 5 {
		t.Fatalf("reloaded AutoLockMinutes() = %d, want persisted 5", got)
	}

	// Explicitly persisting "Off" (0) must survive reload as 0, not fall back
	// to the default.
	if err := reloaded.SetAutoLockMinutes(0); err != nil {
		t.Fatalf("SetAutoLockMinutes(0): %v", err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatalf("reload after off: %v", err)
	}
	if got := again.AutoLockMinutes(); got != 0 {
		t.Fatalf("reloaded AutoLockMinutes() = %d, want persisted 0 (Off)", got)
	}
}

// TestAutoLockRejectsInvalidValues: only the documented options are accepted;
// an out-of-set value is rejected without mutating the in-memory value or
// touching disk.
func TestAutoLockRejectsInvalidValues(t *testing.T) {
	for _, bad := range []int{-1, 2, 10, 60, 1000} {
		path := tmpPath(t)
		s, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if err := s.SetAutoLockMinutes(bad); !errors.Is(err, ErrInvalidAutoLockMinutes) {
			t.Fatalf("SetAutoLockMinutes(%d) error = %v, want ErrInvalidAutoLockMinutes", bad, err)
		}
		if got := s.AutoLockMinutes(); got != defaultAutoLockMinutes {
			t.Fatalf("rejected SetAutoLockMinutes(%d) must leave the default in place, got %d", bad, got)
		}
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("rejected SetAutoLockMinutes(%d) must not write a settings file", bad)
		}
	}
}

// TestAutoLockAllOptionsAccepted: every documented option round-trips.
func TestAutoLockAllOptionsAccepted(t *testing.T) {
	for _, v := range AutoLockOptions {
		path := tmpPath(t)
		s, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if err := s.SetAutoLockMinutes(v); err != nil {
			t.Fatalf("SetAutoLockMinutes(%d): %v", v, err)
		}
		if got := s.AutoLockMinutes(); got != v {
			t.Fatalf("AutoLockMinutes() = %d, want %d", got, v)
		}
	}
}

// TestAutoLockMinutesFallsBackOnInvalidPersistedValue: a settings file that
// was hand-edited (or written by an older/newer version with a different
// option set) can contain an auto_lock_minutes value outside AutoLockOptions.
// AutoLockMinutes must not pass such a value through as-is — it must fall
// back to the default, the same as an absent value.
func TestAutoLockMinutesFallsBackOnInvalidPersistedValue(t *testing.T) {
	for _, bad := range []int{-1, 2, 10, 60, 1000} {
		v := bad
		s := &Store{
			d: data{
				Version:         settingsVersion,
				AutoLockMinutes: &v,
			},
		}
		if got := s.AutoLockMinutes(); got != defaultAutoLockMinutes {
			t.Fatalf("AutoLockMinutes() with invalid persisted %d = %d, want default %d", bad, got, defaultAutoLockMinutes)
		}
	}
}

func TestSetAutoLockMinutesRollsBackOnPersistError(t *testing.T) {
	initial := 5
	s := &Store{
		path: filepath.Join(t.TempDir(), "missing-parent", "settings.json"),
		d: data{
			Version:         settingsVersion,
			AutoLockMinutes: &initial,
		},
	}

	if err := s.SetAutoLockMinutes(30); err == nil {
		t.Fatal("SetAutoLockMinutes should fail when the settings directory is missing")
	}
	if got := s.AutoLockMinutes(); got != initial {
		t.Fatalf("failed SetAutoLockMinutes must leave the in-memory setting unchanged, got %d", got)
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
