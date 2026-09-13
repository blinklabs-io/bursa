package multisig

import (
	"encoding/hex"
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
	addedNames []string
	addedNets  []string
	addErr     error
	listErr    error
	swallowAdd bool // accept the add but do not record it, simulating a silent loss
}

func (f *fakeVault) AddScriptWallet(id, name, network string, s ScriptWallet, _ string) error {
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
		f.addedNames = append(f.addedNames, name)
		f.addedNets = append(f.addedNets, network)
	}
	return nil
}

func (f *fakeVault) ScriptWallets() ([]ScriptWalletRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	wallets := make([]ScriptWalletRecord, 0, len(f.added))
	for i, s := range f.added {
		wallets = append(wallets, ScriptWalletRecord{
			ID: f.addedIDs[i], Name: f.addedNames[i], Network: f.addedNets[i],
			Policy: s.Policy, ScriptCBOR: s.ScriptCBOR,
			ScriptAddress: s.ScriptAddress,
		})
	}
	return wallets, nil
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
			Policy: Policy{Threshold: 2, Participants: []Participant{
				{KeyHashHex: strings.Repeat("a", 56)},
				{KeyHashHex: strings.Repeat("c", 56)},
			}},
			ScriptCBOR:    scriptCBORFor(Policy{Threshold: 2, Participants: []Participant{{KeyHashHex: strings.Repeat("a", 56)}, {KeyHashHex: strings.Repeat("c", 56)}}}),
			ScriptAddress: "addr1_script_one",
		},
		{
			ID: "b", Label: "Ops", Network: "mainnet",
			Policy:        Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: strings.Repeat("b", 56)}}},
			ScriptCBOR:    scriptCBORFor(Policy{Threshold: 1, Participants: []Participant{{KeyHashHex: strings.Repeat("b", 56)}}}),
			ScriptAddress: "addr1_script_two",
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

func TestMigrateRejectsDistinctIDsSharingAnAddress(t *testing.T) {
	accounts := twoAccounts()
	// A shared address is not sufficient to establish identity. The two records
	// must not be collapsed because callers may still hold either legacy ID.
	dupe := accounts[0]
	dupe.ID = "a-again"
	path := writeStore(t, append(accounts, dupe))
	v := &fakeVault{}

	if _, err := MigrateStoreToVault(path, v, "vault-pw"); err == nil {
		t.Fatal("migration must reject distinct IDs sharing a script address")
	}
	if len(v.added) != 0 {
		t.Fatalf("preflight must not partially write distinct identities: got %d", len(v.added))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("legacy store must survive a conflicting migration: %v", err)
	}
}

func TestMigrateRejectsVaultIdentityCollision(t *testing.T) {
	accounts := twoAccounts()
	path := writeStore(t, accounts)
	v := &fakeVault{
		added:    []ScriptWallet{{ScriptCBOR: accounts[0].ScriptCBOR, ScriptAddress: accounts[0].ScriptAddress}},
		addedIDs: []string{"other-id"}, addedNames: []string{"Other"}, addedNets: []string{"mainnet"},
	}

	if _, err := MigrateStoreToVault(path, v, "vault-pw"); err == nil {
		t.Fatal("migration must reject a vault identity collision")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("legacy store must survive a vault identity collision: %v", err)
	}
}

// scriptCBORFor builds the native script a policy describes, hex-encoded the
// way a stored record carries it. Fixtures use real scripts because the
// migration now decodes what it is about to delete the only copy of — a
// stand-in like "8201" is exactly the unusable record it must refuse.
func scriptCBORFor(p Policy) string {
	ns, err := composeScript(p)
	if err != nil {
		panic("fixture policy does not compose: " + err.Error())
	}
	return hex.EncodeToString(ns.Cbor())
}

// The migration deletes the store after verifying the copy by string
// comparison, which a malformed script passes as readily as a good one — so a
// record whose CBOR no longer decodes would be "migrated" into the vault and
// its only usable copy removed. The preflight refuses it instead, and the
// preflight runs before any write, so the file survives.
func TestMigrateRefusesUnusableScriptCBORAndKeepsTheFile(t *testing.T) {
	accounts := twoAccounts()
	accounts[1].ScriptCBOR = "8201" // decodes as hex, not as a native script
	path := writeStore(t, accounts)
	v := &fakeVault{}

	if _, err := MigrateStoreToVault(path, v, "vault-pw"); err == nil {
		t.Fatal("migration should refuse a record whose script does not decode")
	}
	if len(v.added) != 0 {
		t.Fatalf("nothing should have been written: %d added", len(v.added))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("store file must survive: %v", err)
	}
}

// Policy comparison decides whether a legacy record matches the vault record
// that would replace it. Decoded through any, JSON numbers become float64 and
// two policies differing past 2^53 compare equal — the migration would then
// delete the source as an already-migrated duplicate of a record it does not
// actually match.
func TestJSONEqualKeepsIntegerPrecision(t *testing.T) {
	a := []byte(`{"threshold":9007199254740993}`)
	b := []byte(`{"threshold":9007199254740992}`)
	if jsonEqual(a, b) {
		t.Fatal("policies differing by one must not compare equal")
	}
	if !jsonEqual(a, []byte(`{"threshold":9007199254740993}`)) {
		t.Fatal("identical policies must compare equal")
	}
}
