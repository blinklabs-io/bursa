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

package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
)

// writeFormat1Vault writes a genuine legacy (format 1) vault to path: the index
// is sealed DIRECTLY under the vault password (no key section, no VEK), exactly
// as the pre-VEK code wrote it. It optionally includes one spend-password-sealed
// seed blob so the migration is exercised with seeds present. seal must be the
// same primitive the Vault under test uses (the cheap test KDF) so the produced
// blobs decrypt.
func writeFormat1Vault(t *testing.T, path string, seal keystore.Sealer, idx *index, seeds map[string]keystore.Container) {
	t.Helper()
	plain, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	sealed, err := seal(plain, vaultPw)
	if err != nil {
		t.Fatalf("seal index: %v", err)
	}
	var idxContainer keystore.Container
	if err := json.Unmarshal(sealed, &idxContainer); err != nil {
		t.Fatalf("unmarshal index container: %v", err)
	}
	if seeds == nil {
		seeds = map[string]keystore.Container{}
	}
	// A format-1 envelope: format == 1, NO key section.
	legacy := struct {
		Format int                           `json:"format"`
		Index  keystore.Container            `json:"index"`
		Seeds  map[string]keystore.Container `json:"seeds"`
	}{
		Format: legacyFormatVersion,
		Index:  idxContainer,
		Seeds:  seeds,
	}
	out, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy envelope: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write legacy vault: %v", err)
	}
}

// sealSeed seals a mnemonic under a spend password into a Container, mirroring
// how the vault stores a seed, for building a format-1 fixture with a wallet.
func sealSeed(t *testing.T, seal keystore.Sealer, mnemonic, spendPassword string) keystore.Container {
	t.Helper()
	blob, err := seal([]byte(mnemonic), spendPassword)
	if err != nil {
		t.Fatalf("seal seed: %v", err)
	}
	var c keystore.Container
	if err := json.Unmarshal(blob, &c); err != nil {
		t.Fatalf("unmarshal seed container: %v", err)
	}
	return c
}

// TestFormat1VaultUnlocksAndUpgrades is the critical backward-compatibility
// acceptance criterion: a real format-1 vault MUST still open with its original
// password, and the new code transparently upgrades it to format 2 — after which
// it still opens with the same password, and any seed still decrypts with its
// own spend password.
func TestFormat1VaultUnlocksAndUpgrades(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	seal, open := keystore.CheapTestSealer()

	// Build a format-1 fixture with a single wallet + its spend-password seed.
	id := "legacy-wallet-1"
	idx := &index{Wallets: []WalletMeta{{
		ID:      id,
		Name:    "legacy",
		Network: "preview",
	}}}
	seeds := map[string]keystore.Container{
		id: sealSeed(t, seal, mnemonicA, spendPwA),
	}
	writeFormat1Vault(t, path, seal, idx, seeds)

	// Sanity: the fixture really is format 1 with no key section.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if string(probe["format"]) != "1" {
		t.Fatalf("fixture format = %s, want 1", probe["format"])
	}
	if _, hasKey := probe["key"]; hasKey {
		t.Fatal("format-1 fixture must not have a key section")
	}

	v := New(path)
	v.SetCipher(seal, open)

	// (1) The new code opens the format-1 vault with the ORIGINAL password.
	wallets, err := v.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("Unlock format-1 vault: %v", err)
	}
	if len(wallets) != 1 || wallets[0].ID != id {
		t.Fatalf("format-1 unlock wallets = %+v, want the single legacy wallet", wallets)
	}

	// (2) Unlock upgraded the file in place to format 2 with a key section.
	upgraded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read upgraded: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(upgraded, &env); err != nil {
		t.Fatalf("unmarshal upgraded: %v", err)
	}
	if env.Format != formatVersion {
		t.Fatalf("upgraded format = %d, want %d", env.Format, formatVersion)
	}
	if env.Key == nil || env.Key.Password.Ciphertext == "" {
		t.Fatal("upgraded vault missing wrapped-VEK key section")
	}
	if env.Index.Ciphertext == "" {
		t.Fatal("upgraded vault missing index ciphertext")
	}

	// (3) A fresh handle still unlocks the upgraded (format-2) vault with the
	// same password — proving the migration produced a usable format-2 file.
	v2 := New(path)
	v2.SetCipher(seal, open)
	wallets2, err := v2.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("Unlock after upgrade: %v", err)
	}
	if len(wallets2) != 1 || wallets2[0].ID != id {
		t.Fatalf("post-upgrade wallets = %+v, want the single legacy wallet", wallets2)
	}

	// (4) The seed still decrypts under its own spend password (seeds were not
	// re-keyed under the VEK — they stay spend-password-only).
	seed, err := v2.UnlockSeed(spendPwA)
	if err != nil {
		t.Fatalf("UnlockSeed after upgrade: %v", err)
	}
	if string(seed) != mnemonicA {
		t.Fatal("post-upgrade seed mismatch")
	}
}

// TestFormat1VaultWrongPasswordFails confirms a format-1 vault still rejects a
// wrong vault password (and is not upgraded as a side effect of a failed unlock).
func TestFormat1VaultWrongPasswordFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	seal, open := keystore.CheapTestSealer()

	idx := &index{Wallets: []WalletMeta{}}
	writeFormat1Vault(t, path, seal, idx, nil)

	v := New(path)
	v.SetCipher(seal, open)
	if _, err := v.Unlock("wrong-vault-password"); err == nil {
		t.Fatal("Unlock with wrong password on a format-1 vault should fail")
	}

	// The file must remain format 1 (a failed unlock must not rewrite it).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(probe["format"]) != "1" {
		t.Fatalf("format after failed unlock = %s, want 1 (unchanged)", probe["format"])
	}
}

func TestFormat1VaultMigrationWriteFailureAbortsUnlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	seal, open := keystore.CheapTestSealer()
	idx := &index{Wallets: []WalletMeta{{
		ID:      "legacy-wallet-1",
		Name:    "legacy",
		Network: "preview",
	}}}
	writeFormat1Vault(t, path, seal, idx, nil)

	persistErr := errors.New("persist unavailable")
	v := New(path)
	v.SetCipher(func([]byte, string) ([]byte, error) {
		return nil, persistErr
	}, open)
	if _, err := v.Unlock(vaultPw); !errors.Is(err, persistErr) {
		t.Fatalf("Unlock error = %v, want migration persistence error", err)
	}
	if _, err := v.Wallets(); !errors.Is(err, ErrLocked) {
		t.Fatalf("Wallets error = %v, want ErrLocked", err)
	}
}

func TestFormat2WithoutWalletCountUnlocksReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	seal, open := keystore.CheapTestSealer()

	v1 := New(path)
	v1.SetCipher(seal, open)
	if err := v1.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	meta, err := v1.AddWallet("main", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("AddWallet: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal vault: %v", err)
	}
	delete(fields, "wallet_count")
	withoutCount, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal vault without wallet_count: %v", err)
	}
	if err := os.WriteFile(path, withoutCount, 0o600); err != nil {
		t.Fatalf("write vault without wallet_count: %v", err)
	}

	// Model a vault mounted read-only. Unlock only needs to read and decrypt this
	// format-2 file; optional cleartext metadata is deferred to a future write.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod vault: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod vault directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = os.Chmod(path, 0o600)
	})

	v2 := New(path)
	v2.SetCipher(seal, open)
	wallets, err := v2.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("Unlock read-only format-2 vault: %v", err)
	}
	if len(wallets) != 1 || wallets[0].ID != meta.ID {
		t.Fatalf("wallets = %+v, want wallet %q", wallets, meta.ID)
	}
	if v2.ActiveID() != meta.ID {
		t.Fatalf("active wallet = %q, want %q", v2.ActiveID(), meta.ID)
	}
	afterUnlock, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vault after unlock: %v", err)
	}
	var afterFields map[string]json.RawMessage
	if err := json.Unmarshal(afterUnlock, &afterFields); err != nil {
		t.Fatalf("unmarshal vault after unlock: %v", err)
	}
	if _, ok := afterFields["wallet_count"]; ok {
		t.Fatal("Unlock unexpectedly rewrote optional wallet_count metadata")
	}
}
