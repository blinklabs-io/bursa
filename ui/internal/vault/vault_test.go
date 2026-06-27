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
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
)

const (
	// A valid BIP39 test mnemonic (the canonical all-"abandon" vector).
	mnemonicA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// A second, distinct valid mnemonic (different last word checksum).
	mnemonicB = "legal winner thank year wave sausage worth useful legal winner thank yellow"

	vaultPw  = "vault-password-xyz"
	spendPwA = "spend-password-aaa"
	spendPwB = "spend-password-bbb"

	window = 4
)

// newTestVault returns a vault backed by a temp file, wired to the cheap test
// KDF so the suite stays fast (production scrypt is ~1 s per seal).
func newTestVault(t *testing.T) *Vault {
	t.Helper()
	v := New(filepath.Join(t.TempDir(), "vault.json"))
	seal, open := keystore.CheapTestSealer()
	v.SetCipher(seal, open)
	return v
}

func TestCreateAndUnlockEmptyVault(t *testing.T) {
	v := newTestVault(t)
	if v.Exists() {
		t.Fatal("Exists() true before Create")
	}
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !v.Exists() {
		t.Fatal("Exists() false after Create")
	}
	if v.Locked() {
		t.Fatal("vault should be unlocked right after Create")
	}
	if got := v.WalletCount(); got != 0 {
		t.Fatalf("WalletCount = %d, want 0", got)
	}

	// Lock then re-unlock to simulate a relaunch (vault password only, no seed).
	v.Lock()
	if !v.Locked() {
		t.Fatal("vault should be locked after Lock")
	}
	wallets, err := v.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if len(wallets) != 0 {
		t.Fatalf("unlocked wallets = %d, want 0", len(wallets))
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.Create(vaultPw); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("second Create = %v, want ErrVaultExists", err)
	}
}

func TestImportWalletCreatesSingleWalletVault(t *testing.T) {
	v := newTestVault(t)
	meta, err := v.ImportWallet("legacy", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}
	if !v.Exists() || v.Locked() {
		t.Fatal("import should create an unlocked vault")
	}
	if v.ActiveID() != meta.ID {
		t.Fatalf("active = %q, want imported wallet %q", v.ActiveID(), meta.ID)
	}
	if v.WalletCount() != 1 {
		t.Fatalf("WalletCount = %d, want 1", v.WalletCount())
	}
	seed, err := v.UnlockSeed(spendPwA)
	if err != nil {
		t.Fatalf("UnlockSeed after import: %v", err)
	}
	if string(seed) != mnemonicA {
		t.Fatal("imported seed mismatch")
	}
	if _, err := v.ImportWallet("again", mnemonicB, "preview", vaultPw, spendPwB, window); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("second ImportWallet = %v, want ErrVaultExists", err)
	}
}

func TestUnlockNoVault(t *testing.T) {
	v := newTestVault(t)
	if _, err := v.Unlock(vaultPw); !errors.Is(err, ErrNoVault) {
		t.Fatalf("Unlock with no vault = %v, want ErrNoVault", err)
	}
}

func TestUnlockWrongVaultPassword(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	v.Lock()
	if _, err := v.Unlock("wrong-vault-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unlock wrong password = %v, want ErrWrongPassword", err)
	}
}

func TestAddWalletReadOnlyAndSpendLayers(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	meta, err := v.AddWallet("main", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("AddWallet: %v", err)
	}
	if meta.Name != "main" || meta.Network != "preview" {
		t.Fatalf("meta = %+v, want name=main network=preview", meta)
	}
	if meta.Account == nil || len(meta.Account.ReceiveAddresses) != window {
		t.Fatalf("meta.Account missing or wrong window: %+v", meta.Account)
	}
	if meta.AccountXpub == "" {
		t.Fatal("meta.AccountXpub should be populated")
	}
	if v.ActiveID() != meta.ID {
		t.Fatalf("added wallet should be active: active=%q id=%q", v.ActiveID(), meta.ID)
	}

	// Layered read-only: relaunch with vault password only reveals the wallet
	// list and read-only material, with NO seed re-entry.
	v.Lock()
	wallets, err := v.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("Unlock after add: %v", err)
	}
	if len(wallets) != 1 {
		t.Fatalf("wallets after unlock = %d, want 1", len(wallets))
	}
	if wallets[0].Account == nil || wallets[0].Account.StakeAddress == "" {
		t.Fatal("read-only account must be available without the spend password")
	}
	// Sole wallet auto-activates.
	if v.ActiveID() != meta.ID {
		t.Fatalf("sole wallet should auto-activate on unlock")
	}

	// Spend layer: the seed decrypts only with the wallet's own spend password.
	seed, err := v.UnlockSeed(spendPwA)
	if err != nil {
		t.Fatalf("UnlockSeed with correct spend password: %v", err)
	}
	if string(seed) != mnemonicA {
		t.Fatalf("decrypted seed mismatch")
	}
	if _, err := v.UnlockSeed("wrong-spend-password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("UnlockSeed wrong password = %v, want ErrWrongPassword", err)
	}
	// The VAULT password must NOT decrypt the seed (different layer).
	if _, err := v.UnlockSeed(vaultPw); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("UnlockSeed with vault password = %v, want ErrWrongPassword (layers are separate)", err)
	}
}

func TestMultipleWalletsActiveSwitch(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	a, err := v.AddWallet("alpha", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("AddWallet alpha: %v", err)
	}
	b, err := v.AddWallet("beta", mnemonicB, "preview", vaultPw, spendPwB, window)
	if err != nil {
		t.Fatalf("AddWallet beta: %v", err)
	}
	if v.WalletCount() != 2 {
		t.Fatalf("WalletCount = %d, want 2", v.WalletCount())
	}
	// beta was added last → active.
	if v.ActiveID() != b.ID {
		t.Fatalf("active = %q, want beta %q", v.ActiveID(), b.ID)
	}

	// Switch to alpha; its seed unlocks under alpha's password.
	if _, err := v.SetActive(a.ID); err != nil {
		t.Fatalf("SetActive alpha: %v", err)
	}
	seed, err := v.UnlockSeed(spendPwA)
	if err != nil || string(seed) != mnemonicA {
		t.Fatalf("alpha seed unlock: err=%v match=%v", err, string(seed) == mnemonicA)
	}
	// beta's password must not unlock alpha's seed.
	if _, err := v.UnlockSeed(spendPwB); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("alpha seed with beta password = %v, want ErrWrongPassword", err)
	}

	// Multiple wallets → unlock does NOT auto-activate.
	v.Lock()
	if _, err := v.Unlock(vaultPw); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if v.ActiveID() != "" {
		t.Fatalf("multi-wallet unlock should not auto-activate, got %q", v.ActiveID())
	}
	if _, err := v.Active(); !errors.Is(err, ErrNoActiveWallet) {
		t.Fatalf("Active with none selected = %v, want ErrNoActiveWallet", err)
	}
}

func TestAddDuplicateWalletRejected(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := v.AddWallet("one", mnemonicA, "preview", vaultPw, spendPwA, window); err != nil {
		t.Fatalf("AddWallet one: %v", err)
	}
	// Same seed (even under a different name/spend password) → same stake address.
	if _, err := v.AddWallet("dup", mnemonicA, "preview", vaultPw, spendPwB, window); !errors.Is(err, ErrDuplicateWallet) {
		t.Fatalf("duplicate add = %v, want ErrDuplicateWallet", err)
	}
}

func TestRemoveWallet(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	a, _ := v.AddWallet("alpha", mnemonicA, "preview", vaultPw, spendPwA, window)
	b, _ := v.AddWallet("beta", mnemonicB, "preview", vaultPw, spendPwB, window)

	if err := v.RemoveWallet(a.ID, vaultPw); err != nil {
		t.Fatalf("RemoveWallet alpha: %v", err)
	}
	if v.WalletCount() != 1 {
		t.Fatalf("WalletCount after remove = %d, want 1", v.WalletCount())
	}
	// alpha's seed is gone.
	if _, err := v.SetActive(a.ID); !errors.Is(err, ErrUnknownWallet) {
		t.Fatalf("SetActive removed wallet = %v, want ErrUnknownWallet", err)
	}
	// beta still works.
	if _, err := v.SetActive(b.ID); err != nil {
		t.Fatalf("SetActive beta: %v", err)
	}
	if seed, err := v.UnlockSeed(spendPwB); err != nil || string(seed) != mnemonicB {
		t.Fatalf("beta seed unlock after remove: err=%v", err)
	}

	if err := v.RemoveWallet("nonexistent", vaultPw); !errors.Is(err, ErrUnknownWallet) {
		t.Fatalf("RemoveWallet unknown = %v, want ErrUnknownWallet", err)
	}
}

func TestOperationsRequireUnlock(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	v.Lock()
	if _, err := v.Wallets(); !errors.Is(err, ErrLocked) {
		t.Fatalf("Wallets while locked = %v, want ErrLocked", err)
	}
	if _, err := v.AddWallet("x", mnemonicA, "preview", vaultPw, spendPwA, window); !errors.Is(err, ErrLocked) {
		t.Fatalf("AddWallet while locked = %v, want ErrLocked", err)
	}
	if _, err := v.UnlockSeed(spendPwA); !errors.Is(err, ErrLocked) {
		t.Fatalf("UnlockSeed while locked = %v, want ErrLocked", err)
	}
}

// TestSeedsAbsentFromIndexCiphertext is a defense-in-depth check that a wallet's
// mnemonic never appears in the index ciphertext (which is sealed under the
// vault password). The seed lives only in the separate spend-password blob.
func TestNoPlaintextSeedAtRest(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := v.AddWallet("main", mnemonicA, "preview", vaultPw, spendPwA, window); err != nil {
		t.Fatalf("AddWallet: %v", err)
	}
	blob, err := os.ReadFile(v.path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// The raw mnemonic words must not appear anywhere in the on-disk file.
	if bytes.Contains(blob, []byte(mnemonicA)) {
		t.Fatal("plaintext mnemonic found in vault file at rest")
	}
	if bytes.Contains(blob, []byte("abandon")) {
		t.Fatal("plaintext seed word found in vault file at rest")
	}
	// The on-disk envelope must carry an encrypted index and a seed blob.
	var env envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		t.Fatalf("Unmarshal envelope: %v", err)
	}
	if env.Format != formatVersion {
		t.Fatalf("format = %d, want %d", env.Format, formatVersion)
	}
	if env.Index.Ciphertext == "" {
		t.Fatal("index ciphertext empty")
	}
	if len(env.Seeds) != 1 {
		t.Fatalf("seeds = %d, want 1", len(env.Seeds))
	}
	for _, s := range env.Seeds {
		if s.KDF != "scrypt" || s.Ciphertext == "" {
			t.Fatalf("seed blob not a scrypt container: %+v", s)
		}
	}
}

func TestPersistenceAcrossHandles(t *testing.T) {
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

	// A fresh handle (simulating a process restart) sees the same vault.
	v2 := New(path)
	v2.SetCipher(seal, open)
	if !v2.Exists() {
		t.Fatal("second handle does not see the vault file")
	}
	wallets, err := v2.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("Unlock on fresh handle: %v", err)
	}
	if len(wallets) != 1 || wallets[0].ID != meta.ID {
		t.Fatalf("fresh-handle wallets = %+v, want the one added", wallets)
	}
	seed, err := v2.UnlockSeed(spendPwA)
	if err != nil || string(seed) != mnemonicA {
		t.Fatalf("fresh-handle seed unlock: err=%v", err)
	}
}
