package multisig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeVault records what the migration puts in and can be made to fail, so the
// "do not delete unless it really landed" guarantees are testable.
type fakeVault struct {
	added      []ScriptWallet
	addedIDs   []string
	addErr     error
	listErr    error
	swallowAdd bool // accept the add but do not record it, simulating a silent loss
}

func (f *fakeVault) AddScriptWallet(id, _, _ string, s ScriptWallet, _ string) error {
	if f.addErr != nil {
		return f.addErr
	}
	// The vault rejects a script address it already holds; mirror that, since
	// it is what a duplicate entry in one legacy file would hit.
	for _, existing := range f.added {
		if existing.ScriptAddress == s.ScriptAddress {
			return errors.New("duplicate wallet")
		}
	}
	if !f.swallowAdd {
		f.added = append(f.added, s)
		f.addedIDs = append(f.addedIDs, id)
	}
	return nil
}

func (f *fakeVault) ScriptAddresses() ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	addrs := make([]string, 0, len(f.added))
	for _, s := range f.added {
		addrs = append(addrs, s.ScriptAddress)
	}
	return addrs, nil
}

func writeStore(t *testing.T, accounts []Account) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "multisig.json")
	b, err := json.Marshal(accounts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func twoAccounts() []Account {
	return []Account{
		{
			ID: "a", Label: "Treasury", Network: "mainnet",
			Policy:     Policy{Threshold: 2, Participants: []Participant{{KeyHashHex: strings.Repeat("a", 56)}}},
			ScriptCBOR: "8201", ScriptAddress: "addr1_script_one",
		},
		{
			ID: "b", Label: "Ops", Network: "mainnet",
			Policy:     Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: strings.Repeat("b", 56)}}},
			ScriptCBOR: "8202", ScriptAddress: "addr1_script_two",
		},
	}
}

func TestMigrateMovesAccountsAndRemovesTheFile(t *testing.T) {
	path := writeStore(t, twoAccounts())
	v := &fakeVault{}

	n, err := MigrateStoreToVault(path, v, "vault-pw")
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if n != 2 {
		t.Fatalf("migrated = %d, want 2", n)
	}
	if len(v.added) != 2 {
		t.Fatalf("vault got %d accounts, want 2", len(v.added))
	}
	// The policy must survive as usable JSON, not as an opaque blob that no
	// longer parses.
	var p Policy
	if err := json.Unmarshal(v.added[0].Policy, &p); err != nil {
		t.Fatalf("policy did not round-trip: %v", err)
	}
	if p.Threshold != 2 {
		t.Fatalf("threshold = %d, want 2", p.Threshold)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("store file should be gone after a verified migration")
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	accounts := twoAccounts()
	path := writeStore(t, accounts)
	v := &fakeVault{}

	if _, err := MigrateStoreToVault(path, v, "vault-pw"); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	// Second run: the file is gone, so this is the steady state every unlock hits.
	n, err := MigrateStoreToVault(path, v, "vault-pw")
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if n != 0 || len(v.added) != 2 {
		t.Fatalf("second run added %d (total %d), want 0 (total 2)", n, len(v.added))
	}

	// And if the file reappears (a restored backup, a downgrade), already-present
	// accounts are skipped rather than duplicated.
	path2 := writeStore(t, accounts)
	n, err = MigrateStoreToVault(path2, v, "vault-pw")
	if err != nil {
		t.Fatalf("third migrate: %v", err)
	}
	if n != 0 || len(v.added) != 2 {
		t.Fatalf("re-migrate added %d (total %d), want 0 (total 2)", n, len(v.added))
	}
}

func TestMigrateKeepsTheFileWhenAnAddFails(t *testing.T) {
	path := writeStore(t, twoAccounts())
	v := &fakeVault{addErr: errors.New("vault is full of bees")}

	if _, err := MigrateStoreToVault(path, v, "vault-pw"); err == nil {
		t.Fatal("expected an error when the vault rejects the account")
	}
	// The whole point: a failed migration must not be a data-losing one.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("store file must survive a failed migration: %v", err)
	}
}

func TestMigrateKeepsTheFileWhenVerificationFails(t *testing.T) {
	path := writeStore(t, twoAccounts())
	// Adds "succeed" but nothing lands — the case the verification step exists
	// for, and the one that would silently destroy accounts without it.
	v := &fakeVault{swallowAdd: true}

	_, err := MigrateStoreToVault(path, v, "vault-pw")
	if err == nil {
		t.Fatal("expected an error when the accounts are not in the vault afterwards")
	}
	if !strings.Contains(err.Error(), "refusing to remove") {
		t.Fatalf("error should say why the file was kept, got: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("store file must survive failed verification: %v", err)
	}
}

func TestMigrateWithNoStoreFileIsSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multisig.json")
	v := &fakeVault{}

	n, err := MigrateStoreToVault(path, v, "vault-pw")
	if err != nil {
		t.Fatalf("a missing store is the steady state, not an error: %v", err)
	}
	if n != 0 {
		t.Fatalf("migrated = %d, want 0", n)
	}
}

func TestMigrateRemovesAnEmptyStore(t *testing.T) {
	path := writeStore(t, nil)
	v := &fakeVault{}

	if _, err := MigrateStoreToVault(path, v, "vault-pw"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an empty store has nothing to lose and should be retired")
	}
}

func TestMigrateKeepsTheFileWhenTheVaultCannotBeRead(t *testing.T) {
	path := writeStore(t, twoAccounts())
	v := &fakeVault{listErr: errors.New("locked")}

	if _, err := MigrateStoreToVault(path, v, "vault-pw"); err == nil {
		t.Fatal("expected an error when existing wallets cannot be listed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("store file must survive: %v", err)
	}
}

func TestMigratePreservesTheAccountID(t *testing.T) {
	path := writeStore(t, twoAccounts())
	v := &fakeVault{}

	if _, err := MigrateStoreToVault(path, v, "vault-pw"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Links and requests already reference these ids. A migration that renames
	// what it moves breaks every one of them.
	if len(v.addedIDs) != 2 || v.addedIDs[0] != "a" || v.addedIDs[1] != "b" {
		t.Fatalf("ids = %v, want the legacy [a b]", v.addedIDs)
	}
}

func TestMigrateToleratesADuplicateInsideTheStore(t *testing.T) {
	accounts := twoAccounts()
	// The same script address twice: the vault rejects the second, so without
	// tracking what this run already wrote the migration would fail having
	// actually succeeded.
	dupe := accounts[0]
	dupe.ID = "a-again"
	path := writeStore(t, append(accounts, dupe))
	v := &fakeVault{}

	n, err := MigrateStoreToVault(path, v, "vault-pw")
	if err != nil {
		t.Fatalf("migrate with a duplicated entry: %v", err)
	}
	if n != 2 {
		t.Fatalf("migrated = %d, want 2 (the duplicate skipped)", n)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a completed migration should still retire the file")
	}
}
