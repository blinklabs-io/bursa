package multisig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
)

// VaultSink is the slice of the vault this migration needs: somewhere to put a
// script account, and a way to see what is already there. Kept as an interface
// so this package does not depend on the vault package (the dependency runs the
// other way — the vault must not know what a multi-signature policy is).
type VaultSink interface {
	// id carries the legacy account's own identifier, so references to it keep
	// resolving after the move.
	AddScriptWallet(id, name, network string, script ScriptWallet, vaultPassword string) error
	ScriptWallets() ([]ScriptWalletRecord, error)
}

// ScriptWalletRecord is the identity-bearing portion of a script wallet that a
// migration needs in order to distinguish an already-migrated account from a
// different legacy account that happens to derive the same address.
type ScriptWalletRecord struct {
	ID            string
	Name          string
	Network       string
	Policy        json.RawMessage
	ScriptCBOR    string
	ScriptAddress string
}

// ScriptWallet is the material the vault stores for a script account. It
// mirrors vault.ScriptMeta without importing it.
type ScriptWallet struct {
	Policy        json.RawMessage
	ScriptCBOR    string
	ScriptAddress string
}

// MigrateStoreToVault moves saved multi-signature accounts out of the standalone
// JSON store and into the vault, then removes the file.
//
// The store predates the vault: it was written when multi-signature accounts had
// nowhere else to live, as a plain file holding only public material (key
// hashes, the script, its address). Moving it into the vault index puts it
// behind the vault password and lets these accounts appear as wallets rather
// than as a screen of their own.
//
// Safety properties, in the order they matter:
//
//   - Idempotent. Accounts already in the vault (matched on their complete
//     identity) are skipped, so an interrupted run resumes cleanly and a
//     completed one is a no-op.
//   - The file is removed only after a VERIFIED write: every account is
//     re-read back out of the vault and confirmed present. A partial or failed
//     migration leaves the file untouched, so nothing is lost.
//   - A missing file is success, not an error — that is the steady state after
//     the first run and for every wallet created since.
func MigrateStoreToVault(storePath string, v VaultSink, vaultPassword string) (migrated int, err error) {
	accounts, err := readStoreFile(storePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read multisig store: %w", err)
	}
	if len(accounts) == 0 {
		// An empty store has nothing to lose, so retiring the file is safe.
		return 0, removeStoreFile(storePath)
	}

	existing, err := v.ScriptWallets()
	if err != nil {
		return 0, fmt.Errorf("read existing script wallets: %w", err)
	}
	have := make(map[string]ScriptWalletRecord, len(existing))
	haveByAddress := make(map[string]ScriptWalletRecord, len(existing))
	for _, a := range existing {
		if err := validateScriptWalletRecord(a); err != nil {
			return 0, fmt.Errorf("invalid existing script wallet: %w", err)
		}
		if prior, ok := have[a.ID]; ok && !sameScriptWalletIdentity(prior, a) {
			return 0, fmt.Errorf("existing vault contains conflicting wallets for id %q", a.ID)
		}
		if prior, ok := haveByAddress[a.ScriptAddress]; ok && prior.ID != a.ID {
			return 0, fmt.Errorf("existing vault contains distinct wallets for script address %q", a.ScriptAddress)
		}
		have[a.ID] = a
		haveByAddress[a.ScriptAddress] = a
	}

	// Preflight the complete source before making any write. The destination
	// rejects address collisions, but an address is not an identity: retaining
	// only the first of two legacy IDs would silently orphan references to the
	// second. A collision between distinct IDs is therefore an error, not a
	// duplicate to skip.
	for i, a := range accounts {
		if err := validateLegacyAccount(a); err != nil {
			return 0, fmt.Errorf("legacy account %d: %w", i, err)
		}
		for j := 0; j < i; j++ {
			prior := accounts[j]
			if prior.ScriptAddress == a.ScriptAddress && prior.ID != a.ID {
				return 0, fmt.Errorf(
					"refusing to migrate distinct wallet ids %q and %q sharing script address %q",
					prior.ID, a.ID, a.ScriptAddress,
				)
			}
			if prior.ID == a.ID && !sameLegacyAccountIdentity(prior, a) {
				return 0, fmt.Errorf("legacy wallet id %q has conflicting records", a.ID)
			}
		}
		if prior, ok := have[a.ID]; ok && !sameLegacyToVaultIdentity(a, prior) {
			return 0, fmt.Errorf("legacy wallet id %q conflicts with the vault record", a.ID)
		}
		if prior, ok := haveByAddress[a.ScriptAddress]; ok && prior.ID != a.ID {
			return 0, fmt.Errorf(
				"refusing to migrate legacy wallet id %q: script address %q belongs to vault wallet id %q",
				a.ID, a.ScriptAddress, prior.ID,
			)
		}
	}

	for _, a := range accounts {
		if _, ok := have[a.ID]; ok {
			continue
		}
		policy, err := json.Marshal(a.Policy)
		if err != nil {
			return migrated, fmt.Errorf("encode policy for %q: %w", a.Label, err)
		}
		if err := v.AddScriptWallet(a.ID, a.Label, a.Network, ScriptWallet{
			Policy:        policy,
			ScriptCBOR:    a.ScriptCBOR,
			ScriptAddress: a.ScriptAddress,
		}, vaultPassword); err != nil {
			return migrated, fmt.Errorf("add %q to vault: %w", a.Label, err)
		}
		// Record it immediately so an exact duplicate in the source file is
		// treated as the same identity on this run. Distinct IDs sharing an
		// address were rejected by the preflight above.
		have[a.ID] = ScriptWalletRecord{
			ID: a.ID, Name: a.Label, Network: a.Network, Policy: policy,
			ScriptCBOR: a.ScriptCBOR, ScriptAddress: a.ScriptAddress,
		}
		haveByAddress[a.ScriptAddress] = have[a.ID]
		migrated++
	}

	// Verify before deleting: read the vault back and confirm every account from
	// the file is now in it. Trusting the writes we just made would mean
	// deleting the only other copy on the strength of an unchecked assumption.
	after, err := v.ScriptWallets()
	if err != nil {
		return migrated, fmt.Errorf("verify migrated script wallets: %w", err)
	}
	nowHave := make(map[string]ScriptWalletRecord, len(after))
	for _, a := range after {
		if err := validateScriptWalletRecord(a); err != nil {
			return migrated, fmt.Errorf("invalid migrated script wallet: %w", err)
		}
		nowHave[a.ID] = a
	}
	for _, a := range accounts {
		stored, ok := nowHave[a.ID]
		if !ok || !sameLegacyToVaultIdentity(a, stored) {
			return migrated, fmt.Errorf(
				"refusing to remove %s: wallet id %q is not preserved in the vault",
				storePath, a.ID,
			)
		}
	}

	if err := removeStoreFile(storePath); err != nil {
		return migrated, err
	}
	return migrated, nil
}

func validateLegacyAccount(a Account) error {
	if a.ID == "" {
		return errors.New("wallet id is empty")
	}
	if a.ScriptAddress == "" {
		return fmt.Errorf("wallet id %q has an empty script address", a.ID)
	}
	if a.ScriptCBOR == "" {
		return fmt.Errorf("wallet id %q has empty script CBOR", a.ID)
	}
	return nil
}

func validateScriptWalletRecord(a ScriptWalletRecord) error {
	if a.ID == "" {
		return errors.New("wallet id is empty")
	}
	if a.ScriptAddress == "" {
		return fmt.Errorf("wallet id %q has an empty script address", a.ID)
	}
	return nil
}

func sameLegacyAccountIdentity(a, b Account) bool {
	return a.ID == b.ID && a.Label == b.Label && a.Network == b.Network &&
		a.ScriptCBOR == b.ScriptCBOR && a.ScriptAddress == b.ScriptAddress &&
		reflect.DeepEqual(a.Policy, b.Policy)
}

func sameLegacyToVaultIdentity(a Account, b ScriptWalletRecord) bool {
	policy, err := json.Marshal(a.Policy)
	if err != nil {
		return false
	}
	return a.ID == b.ID && a.Label == b.Name && a.Network == b.Network &&
		a.ScriptCBOR == b.ScriptCBOR && a.ScriptAddress == b.ScriptAddress &&
		jsonEqual(policy, b.Policy)
}

func sameScriptWalletIdentity(a, b ScriptWalletRecord) bool {
	return a.ID == b.ID && a.Name == b.Name && a.Network == b.Network &&
		a.ScriptCBOR == b.ScriptCBOR && a.ScriptAddress == b.ScriptAddress &&
		jsonEqual(a.Policy, b.Policy)
}

func jsonEqual(a, b []byte) bool {
	var left, right any
	return json.Unmarshal(a, &left) == nil && json.Unmarshal(b, &right) == nil &&
		reflect.DeepEqual(left, right)
}

// readStoreFile reads the accounts out of the standalone store without going
// through Service, so a migration never constructs one.
func readStoreFile(path string) ([]Account, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is the app's own data dir
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var accounts []Account
	if err := json.Unmarshal(b, &accounts); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return accounts, nil
}

func removeStoreFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
