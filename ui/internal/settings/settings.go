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

// Package settings persists user-facing app settings in the data dir as a small
// JSON file. It is the source of truth for runtime-configurable behaviour (e.g.
// the lean-node history-expiry profile) that env vars only seed a first-run
// default for. Writes are atomic (temp file + rename) so a crash can never leave
// a half-written settings file, and reads tolerate a missing file (all defaults).
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// settingsVersion lets the on-disk format evolve without a hard break.
const settingsVersion = 1

// maxSettingsLen caps Load's read of the settings file. A real settings file is
// a few hundred bytes; anything larger is not one of ours.
const maxSettingsLen = 64 * 1024

// data is the on-disk shape. Booleans use a pointer so a missing key (absent
// field) is distinguishable from an explicit false — only a present value counts
// as "persisted" for seeding purposes.
type data struct {
	Version       int   `json:"version"`
	HistoryExpiry *bool `json:"history_expiry,omitempty"`
}

// Store is a settings file at Path. It is safe for concurrent use: every method
// takes the mutex, and the in-memory snapshot is the authority once loaded.
type Store struct {
	path string

	mu sync.Mutex
	d  data
}

// Load opens (or initializes) the settings store at path. A missing file is not
// an error — it yields an all-defaults store. A present but corrupt file IS an
// error: silently discarding a user's persisted settings would be surprising.
func Load(path string) (*Store, error) {
	s := &Store{path: path, d: data{Version: settingsVersion}}
	blob, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("read settings: %w", err)
	}
	if len(blob) > maxSettingsLen {
		return nil, fmt.Errorf("settings file exceeds %d bytes", maxSettingsLen)
	}
	var d data
	if err := json.Unmarshal(blob, &d); err != nil {
		return nil, fmt.Errorf("parse settings %s: %w", path, err)
	}
	s.d = d
	return s, nil
}

// HistoryExpiry reports the persisted lean-node profile, defaulting to false
// when no value has ever been persisted.
func (s *Store) HistoryExpiry() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.HistoryExpiry != nil && *s.d.HistoryExpiry
}

// SetHistoryExpiry persists the lean-node profile and atomically writes the file.
func (s *Store) SetHistoryExpiry(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := enabled
	s.d.HistoryExpiry = &v
	return s.writeLocked()
}

// SeedDefault sets the history-expiry default ONLY when no value has been
// persisted yet (first run). It is how an env-var/build default (e.g. BURSA_LEAN,
// on-for-mobile) becomes the initial value without ever overriding a value the
// user has since chosen. It is a no-op once any value is persisted, and only
// touches disk when it actually seeds.
func (s *Store) SeedDefault(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.HistoryExpiry != nil {
		return nil // already persisted — the setting is now the source of truth
	}
	v := enabled
	s.d.HistoryExpiry = &v
	return s.writeLocked()
}

// writeLocked atomically writes the current snapshot. The caller holds s.mu.
// It writes to a temp file in the same directory then renames over the target,
// so a reader never observes a partial write and a crash leaves either the old
// file or the new one — never a truncated one.
func (s *Store) writeLocked() error {
	s.d.Version = settingsVersion
	blob, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".settings-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp settings: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename; after a successful
	// rename the temp name no longer exists, so the Remove is a harmless no-op.
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp settings: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp settings: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp settings: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod temp settings: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace settings: %w", err)
	}
	return nil
}
