package multisig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// VaultSink is the slice of the vault this migration needs: somewhere to put a
// script account, and a way to see what is already there. Kept as an interface
// so this package does not depend on the vault package (the dependency runs the
// other way — the vault must not know what a multi-signature policy is).
type VaultSink interface {
	AddScriptWallet(name, network string, script ScriptWallet, vaultPassword string) error
	ScriptAddresses() ([]string, error)
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
//   - Idempotent. Accounts already in the vault (matched on script address) are
//     skipped, so an interrupted run resumes cleanly and a completed one is a
//     no-op.
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

	existing, err := v.ScriptAddresses()
	if err != nil {
		return 0, fmt.Errorf("read existing script wallets: %w", err)
	}
	have := make(map[string]struct{}, len(existing))
	for _, a := range existing {
		have[a] = struct{}{}
	}

	for _, a := range accounts {
		if _, ok := have[a.ScriptAddress]; ok {
			continue
		}
		policy, err := json.Marshal(a.Policy)
		if err != nil {
			return migrated, fmt.Errorf("encode policy for %q: %w", a.Label, err)
		}
		if err := v.AddScriptWallet(a.Label, a.Network, ScriptWallet{
			Policy:        policy,
			ScriptCBOR:    a.ScriptCBOR,
			ScriptAddress: a.ScriptAddress,
		}, vaultPassword); err != nil {
			return migrated, fmt.Errorf("add %q to vault: %w", a.Label, err)
		}
		migrated++
	}

	// Verify before deleting: read the vault back and confirm every account from
	// the file is now in it. Trusting the writes we just made would mean
	// deleting the only other copy on the strength of an unchecked assumption.
	after, err := v.ScriptAddresses()
	if err != nil {
		return migrated, fmt.Errorf("verify migrated script wallets: %w", err)
	}
	nowHave := make(map[string]struct{}, len(after))
	for _, a := range after {
		nowHave[a] = struct{}{}
	}
	for _, a := range accounts {
		if _, ok := nowHave[a.ScriptAddress]; !ok {
			return migrated, fmt.Errorf(
				"refusing to remove %s: %q is not in the vault after migration",
				storePath, a.Label,
			)
		}
	}

	if err := removeStoreFile(storePath); err != nil {
		return migrated, err
	}
	return migrated, nil
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
