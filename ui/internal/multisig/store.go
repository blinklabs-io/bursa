// Package multisig manages native-script multi-signature accounts: composing the
// N-of-M (optionally time-locked) native script, deriving its address, persisting
// the named account, and building/signing/submitting transactions that spend from
// the script address with co-signer witnesses.
//
// NOTE on persistence: the wallet vault is NOT on this branch, so multi-sig
// accounts are persisted independently in a small JSON file under the data dir
// (see store.go). Migrating this store into the vault is a deferred, post-merge
// concern.
package multisig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// store is an atomic-write JSON file holding the saved multi-sig accounts. It
// mirrors the keystore's at-rest model (a single file under the data dir, mode
// 0600) but writes via a temp-file + rename so a crash never leaves a truncated
// file. The accounts hold only public material (key-hashes, vkeys, the script,
// the script address) — no secrets — so unlike the keystore it is not encrypted.
type store struct {
	path string

	mu       sync.Mutex
	accounts []Account
	loaded   bool
}

func newStore(path string) *store {
	return &store{path: path}
}

// loadLocked reads the file into s.accounts. A missing file is an empty store.
// Callers hold s.mu.
func (s *store) loadLocked() error {
	if s.loaded {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.accounts = nil
			s.loaded = true
			return nil
		}
		return fmt.Errorf("read multisig store: %w", err)
	}
	var accts []Account
	if len(b) > 0 {
		if err := json.Unmarshal(b, &accts); err != nil {
			return fmt.Errorf("decode multisig store: %w", err)
		}
	}
	s.accounts = accts
	s.loaded = true
	return nil
}

// persistLocked atomically writes s.accounts to disk. Callers hold s.mu.
func (s *store) persistLocked() error {
	blob, err := json.MarshalIndent(s.accounts, "", "  ")
	if err != nil {
		return fmt.Errorf("encode multisig store: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".multisig-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below fails before the rename.
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// list returns a copy of the saved accounts.
func (s *store) list() ([]Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	out := make([]Account, len(s.accounts))
	copy(out, s.accounts)
	return out, nil
}

// get returns the account with the given id, or ErrUnknownAccount.
func (s *store) get(id string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return Account{}, err
	}
	for _, a := range s.accounts {
		if a.ID == id {
			return a, nil
		}
	}
	return Account{}, fmt.Errorf("%w: %q", ErrUnknownAccount, id)
}

// add appends a new account and persists. It rejects a duplicate id.
func (s *store) add(a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	for _, existing := range s.accounts {
		if existing.ID == a.ID {
			return fmt.Errorf("multisig account %q already exists", a.ID)
		}
	}
	s.accounts = append(s.accounts, a)
	return s.persistLocked()
}

// remove deletes the account with the given id and persists. It is a no-op (no
// error) if the id is not present, so a double-delete is idempotent.
func (s *store) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	filtered := s.accounts[:0]
	for _, a := range s.accounts {
		if a.ID != id {
			filtered = append(filtered, a)
		}
	}
	s.accounts = filtered
	return s.persistLocked()
}
