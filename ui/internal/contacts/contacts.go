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

// Package contacts persists the user's local address book (saved recipient
// addresses with a friendly name and optional note) in the data dir as a small
// JSON file. It is pure on-device storage: it never makes a network call and
// never imports an address list from anywhere — the wallet's consent law
// requires every external contact (favicon, name-service lookup, etc.) to stay
// off the table for this feature. Writes are atomic (temp file + rename) so a
// crash can never leave a half-written contacts file, and reads tolerate a
// missing file (an empty address book), mirroring internal/settings.
package contacts

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

// contactsVersion lets the on-disk format evolve without a hard break.
const contactsVersion = 1

// maxContactsLen caps Load's read of the contacts file. A real address book is
// at most a few hundred entries; anything larger than this is not one of ours.
const maxContactsLen = 1 * 1024 * 1024

// Per-field caps enforced by Upsert, plus a matching entry-count cap, are
// chosen so that a contacts file at the absolute maximum (maxEntries entries,
// each field at its cap) stays comfortably under maxContactsLen above: this
// keeps the read cap and the write path symmetric, so Upsert can never
// silently produce a file that a later Load would refuse to read back.
// writeLocked also enforces maxContactsLen directly as a defense-in-depth
// backstop, in case these per-field caps are ever bypassed or miscalculated.
const (
	maxNameLen    = 256  // bytes, after trimming
	maxAddressLen = 256  // bytes; real bech32/Byron addresses are far shorter, this is a defensive backstop
	maxNoteLen    = 1024 // bytes, after trimming
	maxEntries    = 500  // hard cap on the number of stored contacts
)

// ErrNotFound is returned by Upsert (update path) and Delete when the given ID
// does not match any stored contact.
var ErrNotFound = errors.New("contact not found")

// ErrInvalidRequest is returned when a contact fails validation: a blank name,
// a blank address, or an address that does not parse as a syntactically valid
// Cardano address.
var ErrInvalidRequest = errors.New("invalid contact")

// Entry is one address-book contact. ID is server-generated and empty on a
// create request; Note is optional.
type Entry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Note    string `json:"note,omitempty"`
}

// data is the on-disk shape.
type data struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Store is a contacts file at Path. It is safe for concurrent use: every
// method takes the mutex, and the in-memory snapshot is the authority once
// loaded.
type Store struct {
	path string

	mu sync.Mutex
	d  data
}

// Load opens (or initializes) the contacts store at path. A missing file is
// not an error — it yields an empty address book. A present but corrupt file
// IS an error: silently discarding a user's saved contacts would be
// surprising.
func Load(path string) (*Store, error) {
	s := &Store{path: path, d: data{Version: contactsVersion}}
	blob, err := readFileCapped(path, maxContactsLen)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s, nil
		}
		if errors.Is(err, errContactsTooLarge) {
			return nil, fmt.Errorf("contacts file exceeds %d bytes", maxContactsLen)
		}
		return nil, fmt.Errorf("read contacts: %w", err)
	}
	var d data
	if err := json.Unmarshal(blob, &d); err != nil {
		return nil, fmt.Errorf("parse contacts %s: %w", path, err)
	}
	// Reject a file from a newer format version outright rather than loading
	// it: writeLocked always stamps the current contactsVersion on save, so
	// silently accepting it here would let this (older) build immediately
	// rewrite the file as v1 on the next Upsert/Delete, permanently dropping
	// any fields a newer version added.
	if d.Version > contactsVersion {
		return nil, fmt.Errorf("contacts file %s has version %d, newer than supported version %d", path, d.Version, contactsVersion)
	}
	d, err = normalizeLoadedData(d)
	if err != nil {
		return nil, fmt.Errorf("contacts file %s is invalid: %w", path, err)
	}
	s.d = d
	return s, nil
}

// LoadOrEmpty behaves like Load, except a bad file (corrupt or oversized)
// never prevents the caller from proceeding: it returns a fresh, empty store
// together with the error Load would have returned, instead of that error
// alone. Contacts are non-essential user data — unlike settings or the vault,
// losing access to the address book must not stop the wallet from starting —
// so callers on the startup path should use this instead of Load, log the
// returned error as a warning, and continue with the empty store. The bad
// file on disk is left untouched (never deleted or overwritten here), so it
// remains available for manual recovery; it will only be overwritten if the
// caller later performs a write (e.g. Upsert) against the returned Store.
func LoadOrEmpty(path string) (*Store, error) {
	s, err := Load(path)
	if err != nil {
		return &Store{path: path, d: data{Version: contactsVersion}}, err
	}
	return s, nil
}

func normalizeLoadedData(d data) (data, error) {
	if len(d.Entries) > maxEntries {
		return data{}, fmt.Errorf("has %d entries, max %d", len(d.Entries), maxEntries)
	}
	normalized := data{Version: d.Version, Entries: make([]Entry, len(d.Entries))}
	seenIDs := make(map[string]struct{}, len(d.Entries))
	for i, entry := range d.Entries {
		id := strings.TrimSpace(entry.ID)
		if id == "" {
			return data{}, fmt.Errorf("entry %d has empty id", i)
		}
		if _, ok := seenIDs[id]; ok {
			return data{}, fmt.Errorf("entry %d duplicates id %q", i, id)
		}
		seenIDs[id] = struct{}{}
		name, addr, note, err := validateEntryFields(entry)
		if err != nil {
			return data{}, fmt.Errorf("entry %d: %w", i, err)
		}
		normalized.Entries[i] = Entry{ID: id, Name: name, Address: addr, Note: note}
	}
	return normalized, nil
}

// List returns a copy of all contacts, sorted by name (case-insensitive, ID as
// a stable tiebreaker) so the UI shows a predictable order regardless of
// insertion order. The returned slice and its elements are safe to mutate
// without affecting the store.
func (s *Store) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, len(s.d.Entries))
	copy(out, s.d.Entries)
	sort.Slice(out, func(i, j int) bool {
		ni, nj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if ni != nj {
			return ni < nj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Upsert creates a new contact (when in.ID is empty) or updates an existing
// one (when in.ID matches a stored contact). Name and Address are required
// (trimmed of surrounding whitespace); Address must parse as a syntactically
// valid Cardano address. Note is optional and trimmed. On success the final,
// normalized Entry is returned.
func (s *Store) Upsert(in Entry) (Entry, error) {
	name, addr, note, err := validateEntryFields(in)
	if err != nil {
		return Entry{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.d

	entry := Entry{Name: name, Address: addr, Note: note}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		if len(s.d.Entries) >= maxEntries {
			return Entry{}, fmt.Errorf("%w: address book is full (max %d contacts)", ErrInvalidRequest, maxEntries)
		}
		gid, err := newID()
		if err != nil {
			return Entry{}, fmt.Errorf("create contact: %w", err)
		}
		entry.ID = gid
		// Appending beyond the current length never touches the elements the
		// old snapshot's slice header can see, so `old` stays valid for
		// rollback even though it shares a backing array with s.d.Entries.
		s.d.Entries = append(s.d.Entries, entry)
	} else {
		idx := indexOf(s.d.Entries, id)
		if idx < 0 {
			return Entry{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		entry.ID = id
		// Copy-on-write: mutating s.d.Entries[idx] in place would also mutate
		// old.Entries (same backing array), corrupting the rollback snapshot.
		updated := make([]Entry, len(s.d.Entries))
		copy(updated, s.d.Entries)
		updated[idx] = entry
		s.d.Entries = updated
	}

	if err := s.persistOrRollback(old); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

func validateEntryFields(in Entry) (name string, addr string, note string, err error) {
	name = strings.TrimSpace(in.Name)
	if name == "" {
		return "", "", "", fmt.Errorf("%w: name is required", ErrInvalidRequest)
	}
	if len(name) > maxNameLen {
		return "", "", "", fmt.Errorf("%w: name exceeds %d bytes", ErrInvalidRequest, maxNameLen)
	}
	addr = strings.TrimSpace(in.Address)
	if addr == "" {
		return "", "", "", fmt.Errorf("%w: address is required", ErrInvalidRequest)
	}
	if len(addr) > maxAddressLen {
		return "", "", "", fmt.Errorf("%w: address exceeds %d bytes", ErrInvalidRequest, maxAddressLen)
	}
	if _, err := lcommon.NewAddress(addr); err != nil {
		return "", "", "", fmt.Errorf("%w: invalid address %q: %w", ErrInvalidRequest, addr, err)
	}
	note = strings.TrimSpace(in.Note)
	if len(note) > maxNoteLen {
		return "", "", "", fmt.Errorf("%w: note exceeds %d bytes", ErrInvalidRequest, maxNoteLen)
	}
	return name, addr, note, nil
}

// Delete removes the contact with the given ID. Returns ErrNotFound if no
// contact has that ID.
func (s *Store) Delete(id string) error {
	id = strings.TrimSpace(id)

	s.mu.Lock()
	defer s.mu.Unlock()
	idx := indexOf(s.d.Entries, id)
	if idx < 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	old := s.d

	remaining := make([]Entry, 0, len(s.d.Entries)-1)
	remaining = append(remaining, s.d.Entries[:idx]...)
	remaining = append(remaining, s.d.Entries[idx+1:]...)
	s.d.Entries = remaining

	if err := s.persistOrRollback(old); err != nil {
		return err
	}
	return nil
}

func (s *Store) persistOrRollback(old data) error {
	if committed, err := s.writeLocked(); err != nil {
		if !committed {
			s.d = old
		}
		return err
	}
	return nil
}

// indexOf returns the index of the entry with the given id, or -1.
func indexOf(entries []Entry, id string) int {
	for i, e := range entries {
		if e.ID == id {
			return i
		}
	}
	return -1
}

// newID returns a 16-byte random hex contact id. Random (not sequential) so an
// id leaks nothing about creation order or contact count. crypto/rand.Read's
// error is propagated rather than ignored: silently swallowing it would risk
// handing back an all-zero (or otherwise under-random) id.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return "", fmt.Errorf("generate contact id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

var errContactsTooLarge = errors.New("contacts file too large")

func readFileCapped(path string, maxLen int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxLen {
		return nil, errContactsTooLarge
	}
	blob, err := io.ReadAll(io.LimitReader(f, maxLen+1))
	if err != nil {
		return nil, err
	}
	if int64(len(blob)) > maxLen {
		return nil, errContactsTooLarge
	}
	return blob, nil
}

// writeLocked atomically writes the current snapshot. The caller holds s.mu.
// It writes to a temp file in the same directory then renames over the
// target, so a reader never observes a partial write and a crash leaves
// either the old file or the new one — never a truncated one. The committed
// return value is true once the target path has been replaced, even if a
// later durability step fails.
func (s *Store) writeLocked() (committed bool, err error) {
	s.d.Version = contactsVersion
	blob, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return false, err
	}
	// Defense in depth: Upsert's per-field and entry-count caps should make
	// this unreachable, but if they're ever bypassed or miscalculated, refuse
	// to write a file Load would then refuse to read back. committed stays
	// false, so the caller rolls back its in-memory snapshot.
	if len(blob) > maxContactsLen {
		return false, fmt.Errorf("contacts write would exceed %d bytes", maxContactsLen)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".contacts-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create temp contacts: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename; after a successful
	// rename the temp name no longer exists, so the Remove is a harmless no-op.
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("write temp contacts: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("sync temp contacts: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close temp contacts: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return false, fmt.Errorf("chmod temp contacts: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return false, fmt.Errorf("replace contacts: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return true, fmt.Errorf("sync contacts dir: %w", err)
	}
	return true, nil
}

var syncDir = syncDirFS

func syncDirFS(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
