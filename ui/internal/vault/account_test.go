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
	"errors"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// reopenVault opens a second Vault handle over the same file (cheap cipher) so a
// test can assert on-disk persistence after a lock/relaunch.
func reopenVault(t *testing.T, path string) *Vault {
	t.Helper()
	v := New(path)
	seal, open := keystore.CheapTestSealer()
	v.SetCipher(seal, open)
	return v
}

// TestExistingWalletDefaultsToAccountZero: a wallet created without any
// AddAccount exposes exactly one account (index 0) and selects it by default.
func TestExistingWalletDefaultsToAccountZero(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	meta, err := v.AddWallet("main", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("AddWallet: %v", err)
	}
	if meta.ActiveAccountIndex != 0 {
		t.Fatalf("ActiveAccountIndex = %d, want 0", meta.ActiveAccountIndex)
	}
	if got := len(meta.AccountList()); got != 1 {
		t.Fatalf("AccountList len = %d, want 1", got)
	}
	if meta.ActiveAccount() == nil || meta.ActiveAccount().AccountIndex != 0 {
		t.Fatalf("ActiveAccount = %+v, want index 0", meta.ActiveAccount())
	}
	if v.ActiveAccountIndexFor(meta.ID) != 0 {
		t.Fatalf("ActiveAccountIndexFor = %d, want 0", v.ActiveAccountIndexFor(meta.ID))
	}
}

// TestAddAccountThenSelectPersists is the core multi-account flow: derive a
// second account, switch to it, and confirm the switch survives a reload
// (persisted in the cleartext active-accounts map).
func TestAddAccountThenSelectPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := reopenVault(t, path)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	meta, err := v.AddWallet("main", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("AddWallet: %v", err)
	}
	id := meta.ID

	// Derive account #1.
	updated, err := v.AddAccount(id, vaultPw, spendPwA, 1, window)
	if err != nil {
		t.Fatalf("AddAccount(1): %v", err)
	}
	if len(updated.AccountList()) != 2 {
		t.Fatalf("after AddAccount, AccountList len = %d, want 2", len(updated.AccountList()))
	}
	acct0 := updated.AccountByIndex(0)
	acct1 := updated.AccountByIndex(1)
	if acct0 == nil || acct1 == nil {
		t.Fatalf("missing derived accounts: acct0=%v acct1=%v", acct0, acct1)
	}
	if acct0.StakeAddress == acct1.StakeAddress {
		t.Fatalf("account 0 and 1 share stake address %q", acct0.StakeAddress)
	}
	// AddAccount must NOT change the active selection yet.
	if updated.ActiveAccountIndex != 0 {
		t.Fatalf("ActiveAccountIndex after AddAccount = %d, want 0", updated.ActiveAccountIndex)
	}

	// Select account #1.
	sel, err := v.SelectAccount(id, 1)
	if err != nil {
		t.Fatalf("SelectAccount(1): %v", err)
	}
	if sel.ActiveAccountIndex != 1 {
		t.Fatalf("selected ActiveAccountIndex = %d, want 1", sel.ActiveAccountIndex)
	}
	if sel.ActiveAccount().AccountIndex != 1 {
		t.Fatalf("ActiveAccount index = %d, want 1", sel.ActiveAccount().AccountIndex)
	}

	// Reopen from disk: the selection must persist and the account list too.
	v2 := reopenVault(t, path)
	wallets, err := v2.Unlock(vaultPw)
	if err != nil {
		t.Fatalf("re-Unlock: %v", err)
	}
	if len(wallets) != 1 {
		t.Fatalf("reloaded wallet count = %d, want 1", len(wallets))
	}
	if wallets[0].ActiveAccountIndex != 1 {
		t.Fatalf("reloaded ActiveAccountIndex = %d, want 1 (selection not persisted)", wallets[0].ActiveAccountIndex)
	}
	if len(wallets[0].AccountList()) != 2 {
		t.Fatalf("reloaded AccountList len = %d, want 2", len(wallets[0].AccountList()))
	}
	if v2.ActiveAccountIndexFor(id) != 1 {
		t.Fatalf("reloaded ActiveAccountIndexFor = %d, want 1", v2.ActiveAccountIndexFor(id))
	}
}

// TestSelectBackToZeroClearsPersistedEntry: selecting index 0 removes the map
// entry (keeping single-account vaults byte-clean) while still reporting 0.
func TestSelectBackToZeroClearsPersistedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := reopenVault(t, path)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	meta, err := v.AddWallet("main", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("AddWallet: %v", err)
	}
	if _, err := v.AddAccount(meta.ID, vaultPw, spendPwA, 1, window); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	if _, err := v.SelectAccount(meta.ID, 1); err != nil {
		t.Fatalf("SelectAccount(1): %v", err)
	}
	back, err := v.SelectAccount(meta.ID, 0)
	if err != nil {
		t.Fatalf("SelectAccount(0): %v", err)
	}
	if back.ActiveAccountIndex != 0 {
		t.Fatalf("ActiveAccountIndex = %d, want 0", back.ActiveAccountIndex)
	}
	env := readEnvelopeFile(t, path)
	if _, ok := env.ActiveAccounts[meta.ID]; ok {
		t.Fatalf("active-accounts map still holds an entry after selecting 0: %v", env.ActiveAccounts)
	}
}

// TestAddAccountErrors covers the rejection paths.
func TestAddAccountErrors(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	meta, err := v.AddWallet("main", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("AddWallet: %v", err)
	}

	// Wrong spend password → ErrWrongPassword.
	if _, err := v.AddAccount(meta.ID, vaultPw, "wrong-spend-password", 1, window); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("AddAccount wrong spend pw = %v, want ErrWrongPassword", err)
	}
	// Wrong vault password → ErrWrongPassword.
	if _, err := v.AddAccount(meta.ID, "wrong-vault-password", spendPwA, 1, window); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("AddAccount wrong vault pw = %v, want ErrWrongPassword", err)
	}
	// Unknown wallet id.
	if _, err := v.AddAccount("nope", vaultPw, spendPwA, 1, window); !errors.Is(err, ErrUnknownWallet) {
		t.Fatalf("AddAccount unknown wallet = %v, want ErrUnknownWallet", err)
	}
	// Add index 1, then a duplicate add must be rejected.
	if _, err := v.AddAccount(meta.ID, vaultPw, spendPwA, 1, window); err != nil {
		t.Fatalf("AddAccount(1): %v", err)
	}
	if _, err := v.AddAccount(meta.ID, vaultPw, spendPwA, 1, window); !errors.Is(err, ErrDuplicateAccount) {
		t.Fatalf("duplicate AddAccount = %v, want ErrDuplicateAccount", err)
	}
}

// TestSelectUnknownAccountRejected: cannot select an account that was never
// derived.
func TestSelectUnknownAccountRejected(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	meta, err := v.AddWallet("main", mnemonicA, "preview", vaultPw, spendPwA, window)
	if err != nil {
		t.Fatalf("AddWallet: %v", err)
	}
	if _, err := v.SelectAccount(meta.ID, 7); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("SelectAccount underived = %v, want ErrUnknownAccount", err)
	}
}

// TestAddAccountRejectedForHardwareWallet: seedless wallets cannot derive a new
// hardened account.
func TestAddAccountRejectedForHardwareWallet(t *testing.T) {
	v := newTestVault(t)
	if err := v.Create(vaultPw); err != nil {
		t.Fatalf("Create: %v", err)
	}
	xpub, err := wallet.AccountXpub(mnemonicB)
	if err != nil {
		t.Fatalf("AccountXpub: %v", err)
	}
	meta, err := v.AddHardwareWallet("hw", xpub, "preview", vaultPw, 0, window)
	if err != nil {
		t.Fatalf("AddHardwareWallet: %v", err)
	}
	if _, err := v.AddAccount(meta.ID, vaultPw, spendPwA, 1, window); !errors.Is(err, ErrNoSeed) {
		t.Fatalf("AddAccount on hardware wallet = %v, want ErrNoSeed", err)
	}
}
