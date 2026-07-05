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
package contacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "contacts.json")
}

// validAddr / validAddr2 are real, checksummed bech32 testnet stake addresses
// built from parts (rather than hand-typed literals) so the bech32 checksum is
// always correct.
func validAddr(t *testing.T, seed byte) string {
	t.Helper()
	hash := make([]byte, lcommon.AddressHashSize)
	hash[0] = seed
	addr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, lcommon.AddressNetworkTestnet, nil, hash)
	if err != nil {
		t.Fatalf("build test address: %v", err)
	}
	return addr.String()
}

// TestLoadMissingFileYieldsEmpty: a missing contacts file is not an error — it
// yields a store with no entries (mirrors settings.Load).
func TestLoadMissingFileYieldsEmpty(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load with no file: %v", err)
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("List() = %v, want empty", got)
	}
}

// TestLoadRejectsCorruptFile: a present-but-corrupt file is a hard error rather
// than silently discarding the user's address book.
func TestLoadRejectsCorruptFile(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load should error on a corrupt contacts file")
	}
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, make([]byte, maxContactsLen+1), 0o600); err != nil {
		t.Fatalf("seed oversized file: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load should reject an oversized contacts file")
	}
	if !strings.Contains(err.Error(), "contacts file exceeds") {
		t.Fatalf("Load error = %q, want size-cap error", err)
	}
}

// TestLoadRejectsNewerVersion: a contacts file stamped with a version newer
// than this build supports must be refused outright, not silently loaded
// (which would let this build immediately downgrade it back to v1 on the
// next write, dropping whatever the newer version added).
func TestLoadRejectsNewerVersion(t *testing.T) {
	path := tmpPath(t)
	future := data{
		Version: contactsVersion + 1,
		Entries: []Entry{{ID: "x", Name: "X", Address: validAddr(t, 99)}},
	}
	blob, err := json.Marshal(future)
	if err != nil {
		t.Fatalf("marshal future-version fixture: %v", err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("seed future-version file: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load should reject a contacts file with a newer version than supported")
	}
}

func TestLoadRejectsInvalidPersistedData(t *testing.T) {
	tooMany := make([]Entry, maxEntries+1)
	for i := range tooMany {
		tooMany[i] = Entry{
			ID:      fmt.Sprintf("id-%d", i),
			Name:    fmt.Sprintf("C%d", i),
			Address: validAddr(t, byte(i)),
		}
	}

	tests := []struct {
		name    string
		fixture data
		want    string
	}{
		{
			name: "invalid address",
			fixture: data{
				Version: contactsVersion,
				Entries: []Entry{{
					ID:      "bad-address",
					Name:    "Bad",
					Address: "not-a-real-address",
				}},
			},
			want: "invalid address",
		},
		{
			name: "oversized name",
			fixture: data{
				Version: contactsVersion,
				Entries: []Entry{{
					ID:      "long-name",
					Name:    strings.Repeat("n", maxNameLen+1),
					Address: validAddr(t, 70),
				}},
			},
			want: "name exceeds",
		},
		{
			name: "oversized note",
			fixture: data{
				Version: contactsVersion,
				Entries: []Entry{{
					ID:      "long-note",
					Name:    "Long Note",
					Address: validAddr(t, 71),
					Note:    strings.Repeat("n", maxNoteLen+1),
				}},
			},
			want: "note exceeds",
		},
		{
			name: "too many entries",
			fixture: data{
				Version: contactsVersion,
				Entries: tooMany,
			},
			want: "entries",
		},
		{
			name: "empty id",
			fixture: data{
				Version: contactsVersion,
				Entries: []Entry{{
					Name:    "Missing ID",
					Address: validAddr(t, 72),
				}},
			},
			want: "empty id",
		},
		{
			name: "duplicate id",
			fixture: data{
				Version: contactsVersion,
				Entries: []Entry{
					{ID: "dup", Name: "One", Address: validAddr(t, 73)},
					{ID: "dup", Name: "Two", Address: validAddr(t, 74)},
				},
			},
			want: "duplicates id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tmpPath(t)
			blob, err := json.Marshal(tt.fixture)
			if err != nil {
				t.Fatalf("marshal fixture: %v", err)
			}
			if err := os.WriteFile(path, blob, 0o600); err != nil {
				t.Fatalf("seed invalid file: %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load should reject invalid persisted contact data")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoadNormalizesPersistedData(t *testing.T) {
	path := tmpPath(t)
	addr := validAddr(t, 75)
	fixture := data{
		Version: contactsVersion,
		Entries: []Entry{{
			ID:      " c1 ",
			Name:    "  Alice  ",
			Address: "  " + addr + "  ",
			Note:    "  friend  ",
		}},
	}
	blob, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("seed unnormalized file: %v", err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := s.List()
	want := Entry{ID: "c1", Name: "Alice", Address: addr, Note: "friend"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("List() = %v, want [%+v]", got, want)
	}
}

// TestLoadOrEmptyToleratesNewerVersion mirrors the corrupt/oversized cases:
// a future-version file must not stop the wallet from starting.
func TestLoadOrEmptyToleratesNewerVersion(t *testing.T) {
	path := tmpPath(t)
	future := data{
		Version: contactsVersion + 1,
		Entries: []Entry{{ID: "x", Name: "X", Address: validAddr(t, 98)}},
	}
	blob, err := json.Marshal(future)
	if err != nil {
		t.Fatalf("marshal future-version fixture: %v", err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("seed future-version file: %v", err)
	}
	s, warn := LoadOrEmpty(path)
	if warn == nil {
		t.Fatal("LoadOrEmpty should return the underlying error as a warning for a newer-version file")
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("List() = %v, want empty store on a newer-version file", got)
	}
}

func TestLoadOrEmptyToleratesInvalidPersistedData(t *testing.T) {
	path := tmpPath(t)
	fixture := data{
		Version: contactsVersion,
		Entries: []Entry{{
			ID:      "bad-address",
			Name:    "Bad",
			Address: "not-a-real-address",
		}},
	}
	blob, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal invalid fixture: %v", err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("seed invalid file: %v", err)
	}
	s, warn := LoadOrEmpty(path)
	if warn == nil {
		t.Fatal("LoadOrEmpty should return the underlying error as a warning for invalid persisted data")
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("List() = %v, want empty store on invalid persisted data", got)
	}
}

// TestUpsertCreateGeneratesIDPersistsAndReloads: creating a contact (no ID
// supplied) generates one, writes the file, and a fresh Load observes it.
func TestUpsertCreateGeneratesIDPersistsAndReloads(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	addr := validAddr(t, 1)
	entry, err := s.Upsert(Entry{Name: "  Alice  ", Address: addr, Note: " friend "})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if entry.ID == "" {
		t.Fatal("Upsert should generate an ID when none is supplied")
	}
	if entry.Name != "Alice" {
		t.Fatalf("Name = %q, want trimmed %q", entry.Name, "Alice")
	}
	if entry.Address != addr {
		t.Fatalf("Address = %q, want %q", entry.Address, addr)
	}
	if entry.Note != "friend" {
		t.Fatalf("Note = %q, want trimmed %q", entry.Note, "friend")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("contacts file not written: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := reloaded.List()
	if len(got) != 1 {
		t.Fatalf("List() after reload = %v, want 1 entry", got)
	}
	if got[0] != entry {
		t.Fatalf("reloaded entry = %+v, want %+v", got[0], entry)
	}
}

func TestUpsertRequiresName(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = s.Upsert(Entry{Name: "   ", Address: validAddr(t, 2)})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Upsert with blank name error = %v, want ErrInvalidRequest", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("a rejected Upsert must not persist anything")
	}
}

func TestUpsertRequiresValidAddress(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = s.Upsert(Entry{Name: "Bob", Address: "not-a-real-address"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Upsert with invalid address error = %v, want ErrInvalidRequest", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("a rejected Upsert must not persist anything")
	}
}

func TestUpsertRequiresAddress(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = s.Upsert(Entry{Name: "Bob", Address: "   "})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Upsert with blank address error = %v, want ErrInvalidRequest", err)
	}
}

// TestUpsertUpdateExistingByID: supplying an existing ID updates that entry in
// place rather than creating a new one.
func TestUpsertUpdateExistingByID(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	addr1 := validAddr(t, 3)
	created, err := s.Upsert(Entry{Name: "Carol", Address: addr1})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	addr2 := validAddr(t, 4)
	updated, err := s.Upsert(Entry{ID: created.ID, Name: "Carol Updated", Address: addr2, Note: "n2"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ID != created.ID {
		t.Fatalf("update changed ID: got %q, want %q", updated.ID, created.ID)
	}
	if updated.Name != "Carol Updated" || updated.Address != addr2 || updated.Note != "n2" {
		t.Fatalf("update did not apply: %+v", updated)
	}

	all := s.List()
	if len(all) != 1 {
		t.Fatalf("List() = %v, want exactly 1 entry after update (no duplicate)", all)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0] != updated {
		t.Fatalf("reloaded = %v, want [%+v]", got, updated)
	}
}

func TestUpsertUpdateUnknownIDReturnsNotFound(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = s.Upsert(Entry{ID: "does-not-exist", Name: "Dave", Address: validAddr(t, 5)})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Upsert with unknown ID error = %v, want ErrNotFound", err)
	}
}

// TestUpsertUpdateDoesNotCorruptOtherEntries verifies that updating one entry
// via copy-on-write doesn't leak into a previously-returned List() snapshot or
// corrupt a rollback path.
func TestUpsertUpdateDoesNotCorruptOtherEntries(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	a, err := s.Upsert(Entry{Name: "A", Address: validAddr(t, 6)})
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	b, err := s.Upsert(Entry{Name: "B", Address: validAddr(t, 7)})
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	snapshot := s.List()

	if _, err := s.Upsert(Entry{ID: a.ID, Name: "A2", Address: validAddr(t, 8)}); err != nil {
		t.Fatalf("update a: %v", err)
	}

	// The earlier snapshot slice must not have been mutated in place.
	for _, e := range snapshot {
		if e.ID == a.ID && e.Name != "A" {
			t.Fatalf("earlier List() snapshot was mutated: %+v", e)
		}
	}
	_ = b
}

func TestDeleteRemovesEntry(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e1, err := s.Upsert(Entry{Name: "Eve", Address: validAddr(t, 9)})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	e2, err := s.Upsert(Entry{Name: "Frank", Address: validAddr(t, 10)})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.Delete(e1.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got := s.List()
	if len(got) != 1 || got[0].ID != e2.ID {
		t.Fatalf("List() after delete = %v, want only %+v", got, e2)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].ID != e2.ID {
		t.Fatalf("reloaded after delete = %v, want only %+v", got, e2)
	}
}

func TestDeleteUnknownIDReturnsNotFound(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s.Delete("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete unknown ID error = %v, want ErrNotFound", err)
	}
}

// TestListSortedByNameCaseInsensitive: List() returns entries in a stable,
// case-insensitive name order regardless of insertion order.
func TestListSortedByNameCaseInsensitive(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := s.Upsert(Entry{Name: "charlie", Address: validAddr(t, 11)}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Upsert(Entry{Name: "Alice", Address: validAddr(t, 12)}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Upsert(Entry{Name: "bob", Address: validAddr(t, 13)}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got := s.List()
	if len(got) != 3 {
		t.Fatalf("List() = %v, want 3 entries", got)
	}
	names := []string{got[0].Name, got[1].Name, got[2].Name}
	want := []string{"Alice", "bob", "charlie"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("List() order = %v, want %v", names, want)
		}
	}
}

func TestListReturnsCopyNotInternalSlice(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := s.Upsert(Entry{Name: "Alice", Address: validAddr(t, 14)}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got := s.List()
	got[0].Name = "mutated"
	got2 := s.List()
	if got2[0].Name == "mutated" {
		t.Fatal("List() leaked internal storage — mutation via one snapshot affected another")
	}
}

func TestUpsertRollsBackOnPersistError(t *testing.T) {
	existing := Entry{ID: "keep-me", Name: "Grace", Address: validAddr(t, 15)}
	s := &Store{
		path: filepath.Join(t.TempDir(), "missing-parent", "contacts.json"),
		d:    data{Version: contactsVersion, Entries: []Entry{existing}},
	}
	_, err := s.Upsert(Entry{Name: "Interloper", Address: validAddr(t, 17)})
	if err == nil {
		t.Fatal("Upsert should fail when the contacts directory is missing")
	}
	if got := s.List(); len(got) != 1 || got[0] != existing {
		t.Fatalf("failed Upsert must leave the in-memory store unchanged, got %v", got)
	}
}

// TestUpsertRejectsOversizedName: a Name over maxNameLen is rejected as a
// validation error before anything is written, so an oversized field can
// never make the contacts file unloadable.
func TestUpsertRejectsOversizedName(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	longName := strings.Repeat("a", maxNameLen+1)
	_, err = s.Upsert(Entry{Name: longName, Address: validAddr(t, 20)})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Upsert with oversized name error = %v, want ErrInvalidRequest", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("a rejected Upsert must not persist anything")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("a rejected Upsert must not create a contacts file, stat err = %v", statErr)
	}
}

// TestUpsertRejectsOversizedNote: mirrors TestUpsertRejectsOversizedName for
// Note — this is the field the root-cause report called out (a large Note is
// the easiest way to blow past the read cap via legitimate-looking traffic).
func TestUpsertRejectsOversizedNote(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	longNote := strings.Repeat("n", maxNoteLen+1)
	_, err = s.Upsert(Entry{Name: "Zed", Address: validAddr(t, 21), Note: longNote})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Upsert with oversized note error = %v, want ErrInvalidRequest", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("a rejected Upsert must not persist anything")
	}
	// The store must remain loadable: no half-valid/unloadable file was written.
	if _, err := Load(path); err != nil {
		t.Fatalf("contacts file became unloadable after a rejected Upsert: %v", err)
	}
}

// TestUpsertRejectsOversizedAddress covers the defensive Address cap. The
// length check runs before bech32/Byron parsing, so an over-length string
// doesn't need to be a syntactically plausible address to be rejected.
func TestUpsertRejectsOversizedAddress(t *testing.T) {
	s, err := Load(tmpPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	longAddr := strings.Repeat("a", maxAddressLen+1)
	_, err = s.Upsert(Entry{Name: "Zed", Address: longAddr})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Upsert with oversized address error = %v, want ErrInvalidRequest", err)
	}
}

// TestUpsertRejectsWhenAddressBookFull: the entry-count cap only applies to
// creates. The store is seeded directly (not via maxEntries real Upsert
// calls) purely to keep the test fast — Upsert's own validation doesn't care
// how the in-memory entries got there.
func TestUpsertRejectsWhenAddressBookFull(t *testing.T) {
	path := tmpPath(t)
	entries := make([]Entry, maxEntries)
	for i := range entries {
		entries[i] = Entry{
			ID:      fmt.Sprintf("id-%d", i),
			Name:    fmt.Sprintf("C%d", i),
			Address: validAddr(t, byte(i)),
		}
	}
	s := &Store{path: path, d: data{Version: contactsVersion, Entries: entries}}

	_, err := s.Upsert(Entry{Name: "Overflow", Address: validAddr(t, 250)})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Upsert beyond maxEntries error = %v, want ErrInvalidRequest", err)
	}
	if got := s.List(); len(got) != maxEntries {
		t.Fatalf("List() = %d entries, want %d (overflow must not persist)", len(got), maxEntries)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("a rejected Upsert must not create a contacts file, stat err = %v", statErr)
	}
}

// TestUpsertRejectsWhenAddressBookFullAllowsUpdate: the maxEntries cap must
// only block creates. Updating one of the existing (at-capacity) entries
// should still succeed.
func TestUpsertRejectsWhenAddressBookFullAllowsUpdate(t *testing.T) {
	path := tmpPath(t)
	entries := make([]Entry, maxEntries)
	for i := range entries {
		entries[i] = Entry{
			ID:      fmt.Sprintf("id-%d", i),
			Name:    fmt.Sprintf("C%d", i),
			Address: validAddr(t, byte(i)),
		}
	}
	s := &Store{path: path, d: data{Version: contactsVersion, Entries: entries}}

	updated, err := s.Upsert(Entry{ID: "id-0", Name: "Updated", Address: validAddr(t, 251)})
	if err != nil {
		t.Fatalf("update at full capacity should succeed: %v", err)
	}
	if updated.Name != "Updated" {
		t.Fatalf("update did not apply: %+v", updated)
	}
	if got := s.List(); len(got) != maxEntries {
		t.Fatalf("List() = %d entries, want unchanged %d", len(got), maxEntries)
	}
}

// TestWriteLockedRejectsOversizedBlob exercises writeLocked's write-side
// maxContactsLen guard directly (bypassing Upsert's per-field caps, which
// would normally prevent this) so the defense-in-depth backstop is verified
// on its own: it must refuse to write, report not-committed, and leave no
// temp file or target file behind.
func TestWriteLockedRejectsOversizedBlob(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "contacts.json")
	huge := Entry{
		ID:      "huge",
		Name:    "Huge",
		Address: validAddr(t, 30),
		Note:    strings.Repeat("x", maxContactsLen),
	}
	s := &Store{path: path, d: data{Version: contactsVersion, Entries: []Entry{huge}}}

	committed, err := s.writeLocked()
	if err == nil {
		t.Fatal("writeLocked should reject a blob larger than maxContactsLen")
	}
	if committed {
		t.Fatal("writeLocked must not report committed when it refuses to write")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("writeLocked must not create the target file when it refuses to write, stat err = %v", statErr)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".contacts-*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("writeLocked left a temp file behind: %v", matches)
	}
}

// TestUpsertRollsBackWhenWriteWouldExceedMaxContactsLen exercises the guard
// through Upsert (not just writeLocked directly): a store carrying an
// oversized "legacy" entry (as if written before the per-field caps existed)
// must reject and roll back an otherwise-ordinary new contact rather than
// commit a file Load would then refuse to read back.
func TestUpsertRollsBackWhenWriteWouldExceedMaxContactsLen(t *testing.T) {
	path := tmpPath(t)
	legacy := Entry{
		ID:      "legacy",
		Name:    "Legacy",
		Address: validAddr(t, 40),
		Note:    strings.Repeat("z", maxContactsLen-256),
	}
	s := &Store{path: path, d: data{Version: contactsVersion, Entries: []Entry{legacy}}}

	_, err := s.Upsert(Entry{Name: "One More", Address: validAddr(t, 41), Note: "small note"})
	if err == nil {
		t.Fatal("Upsert should fail when the resulting file would exceed maxContactsLen")
	}
	if got := s.List(); len(got) != 1 || got[0] != legacy {
		t.Fatalf("failed Upsert must leave the in-memory store unchanged, got %v", got)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("failed Upsert must not create a contacts file, stat err = %v", statErr)
	}
}

// TestLoadOrEmptyToleratesCorruptFile: contacts are non-essential, so a
// corrupt file must yield a usable empty store plus a non-nil warning, never
// a crash — and the bad file must be left on disk untouched for recovery.
func TestLoadOrEmptyToleratesCorruptFile(t *testing.T) {
	path := tmpPath(t)
	const badContent = "{not valid json"
	if err := os.WriteFile(path, []byte(badContent), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	s, warn := LoadOrEmpty(path)
	if warn == nil {
		t.Fatal("LoadOrEmpty should return the underlying error as a warning")
	}
	if s == nil {
		t.Fatal("LoadOrEmpty must return a usable store even on error")
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("List() = %v, want empty store on a corrupt file", got)
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("bad contacts file was removed: %v", readErr)
	}
	if string(raw) != badContent {
		t.Fatalf("bad contacts file was modified: %q", raw)
	}
}

// TestLoadOrEmptyToleratesOversizedFile mirrors the corrupt-file case for an
// oversized file — the other way Load hard-errors.
func TestLoadOrEmptyToleratesOversizedFile(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, make([]byte, maxContactsLen+1), 0o600); err != nil {
		t.Fatalf("seed oversized file: %v", err)
	}
	s, warn := LoadOrEmpty(path)
	if warn == nil {
		t.Fatal("LoadOrEmpty should return the underlying error as a warning")
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("List() = %v, want empty store on an oversized file", got)
	}
}

// TestLoadOrEmptyStoreRemainsWritable: the empty store returned after a bad
// file must still be a fully working Store — a subsequent Upsert succeeds and
// (as an ordinary consequence of writing, not a proactive recovery step)
// overwrites the bad file with a fresh, valid one.
func TestLoadOrEmptyStoreRemainsWritable(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	s, warn := LoadOrEmpty(path)
	if warn == nil {
		t.Fatal("expected a warning error from LoadOrEmpty")
	}
	entry, err := s.Upsert(Entry{Name: "Fresh", Address: validAddr(t, 60)})
	if err != nil {
		t.Fatalf("Upsert on a LoadOrEmpty-recovered store: %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload after recovery: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0] != entry {
		t.Fatalf("reloaded = %v, want [%+v]", got, entry)
	}
}

// TestLoadOrEmptyPassesThroughGoodFile: a valid file behaves exactly like
// Load — no warning, contents preserved.
func TestLoadOrEmptyPassesThroughGoodFile(t *testing.T) {
	path := tmpPath(t)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	entry, err := s.Upsert(Entry{Name: "Good", Address: validAddr(t, 61)})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	reloaded, warn := LoadOrEmpty(path)
	if warn != nil {
		t.Fatalf("LoadOrEmpty on a valid file returned a warning: %v", warn)
	}
	if got := reloaded.List(); len(got) != 1 || got[0] != entry {
		t.Fatalf("LoadOrEmpty = %v, want [%+v]", got, entry)
	}
}

// TestLoadOrEmptyMissingFileYieldsEmptyNoWarning: a missing file is not an
// error for Load, and must not be treated as one by LoadOrEmpty either.
func TestLoadOrEmptyMissingFileYieldsEmptyNoWarning(t *testing.T) {
	s, warn := LoadOrEmpty(tmpPath(t))
	if warn != nil {
		t.Fatalf("LoadOrEmpty on a missing file returned a warning: %v", warn)
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("List() = %v, want empty", got)
	}
}

func TestDeleteRollsBackOnPersistError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "contacts.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e, err := s.Upsert(Entry{Name: "Henry", Address: validAddr(t, 16)})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Make the directory unwritable-by-rename by pointing the store at a path
	// whose parent no longer exists.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove dir: %v", err)
	}

	if err := s.Delete(e.ID); err == nil {
		t.Fatal("Delete should fail when the contacts directory has vanished")
	}
	if got := s.List(); len(got) != 1 || got[0].ID != e.ID {
		t.Fatalf("failed Delete must leave the in-memory store unchanged, got %v", got)
	}
}
