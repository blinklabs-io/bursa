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
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/chain"
	"github.com/blinklabs-io/bursa/ui/internal/contacts"
	"github.com/blinklabs-io/bursa/ui/internal/dex"
	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/poolops"
	"github.com/blinklabs-io/bursa/ui/internal/settings"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/vault"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

type fakeStatuser struct{ s supervisor.Status }

func (f fakeStatuser) Status() supervisor.Status { return f.s }

// fakeVault implements the api.Vault interface. It models the layered model in
// memory: Unlock/Lock toggle locked; AddWallet appends and activates; the active
// wallet drives reads/spends.
type fakeVault struct {
	exists     bool
	locked     bool
	wallets    []vault.WalletMeta
	activeID   string
	createErr  error
	unlockErr  error
	addErr     error
	addCalled  bool
	importErr  error
	imported   bool
	gotName    string
	gotNetwork string
	gotSpend   string
	gotVault   string
	gotSeed    []byte

	// TPM fakes
	tpmStatus          vault.TPMStatusInfo
	enableTPMErr       error
	disableTPMErr      error
	enableTPMCalled    bool
	disableTPMCalled   bool
	enableTPMPassword  string
	enableTPMPCRBound  bool
	disableTPMPassword string
}

type fakeLegacyKeystore struct {
	exists   bool
	mnemonic []byte
	err      error
	gotPw    string
	returned []byte
}

func (f *fakeLegacyKeystore) Exists() bool { return f.exists }

func (f *fakeLegacyKeystore) Unlock(password string) ([]byte, error) {
	f.gotPw = password
	if f.err != nil {
		return nil, f.err
	}
	f.returned = append([]byte(nil), f.mnemonic...)
	return f.returned, nil
}

func sampleAccount(net string) *wallet.Account {
	return &wallet.Account{
		Network:          net,
		StakeAddress:     "stake_test1x",
		ReceiveAddresses: []string{"addr_test1a"},
	}
}

func (f *fakeVault) Exists() bool     { return f.exists }
func (f *fakeVault) Locked() bool     { return f.locked }
func (f *fakeVault) WalletCount() int { return len(f.wallets) }

func (f *fakeVault) Create(_ string) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.exists = true
	f.locked = false
	return nil
}

func (f *fakeVault) Unlock(_ string) ([]vault.WalletMeta, error) {
	if f.unlockErr != nil {
		return nil, f.unlockErr
	}
	f.locked = false
	if len(f.wallets) == 1 {
		f.activeID = f.wallets[0].ID
	}
	return f.wallets, nil
}

func (f *fakeVault) Lock() { f.locked = true; f.activeID = "" }

func (f *fakeVault) Wallets() ([]vault.WalletMeta, error) {
	if f.locked {
		return nil, vault.ErrLocked
	}
	return f.wallets, nil
}

func (f *fakeVault) AddWallet(name, _, network, vaultPw, spendPw string, _ int) (vault.WalletMeta, error) {
	if f.addErr != nil {
		return vault.WalletMeta{}, f.addErr
	}
	f.addCalled = true
	f.gotName = name
	f.gotNetwork = network
	f.gotSpend = spendPw
	f.gotVault = vaultPw
	meta := vault.WalletMeta{ID: "w1", Name: name, Network: network, Account: sampleAccount(network)}
	f.wallets = append(f.wallets, meta)
	f.activeID = meta.ID
	return meta, nil
}

func (f *fakeVault) ImportWallet(name, _, network, vaultPw, spendPw string, _ int) (vault.WalletMeta, error) {
	return f.importWallet(name, nil, network, vaultPw, spendPw)
}

func (f *fakeVault) ImportWalletMnemonicBytes(name string, mnemonic []byte, network, vaultPw, spendPw string, _ int) (vault.WalletMeta, error) {
	return f.importWallet(name, mnemonic, network, vaultPw, spendPw)
}

func (f *fakeVault) importWallet(name string, mnemonic []byte, network, vaultPw, spendPw string) (vault.WalletMeta, error) {
	if f.importErr != nil {
		return vault.WalletMeta{}, f.importErr
	}
	f.imported = true
	f.exists = true
	f.locked = false
	f.gotName = name
	f.gotNetwork = network
	f.gotSpend = spendPw
	f.gotVault = vaultPw
	f.gotSeed = mnemonic
	meta := vault.WalletMeta{ID: "legacy1", Name: name, Network: network, Account: sampleAccount(network)}
	f.wallets = []vault.WalletMeta{meta}
	f.activeID = meta.ID
	return meta, nil
}

func (f *fakeVault) RemoveWallet(id, _ string) error {
	kept := f.wallets[:0:0]
	found := false
	for _, w := range f.wallets {
		if w.ID == id {
			found = true
			continue
		}
		kept = append(kept, w)
	}
	if !found {
		return fmt.Errorf("%w: %q", vault.ErrUnknownWallet, id)
	}
	f.wallets = kept
	if f.activeID == id {
		f.activeID = ""
	}
	return nil
}

func (f *fakeVault) SetActive(id string) (vault.WalletMeta, error) {
	for _, w := range f.wallets {
		if w.ID == id {
			f.activeID = id
			return w, nil
		}
	}
	return vault.WalletMeta{}, fmt.Errorf("%w: %q", vault.ErrUnknownWallet, id)
}

func (f *fakeVault) Active() (vault.WalletMeta, error) {
	if f.activeID == "" {
		return vault.WalletMeta{}, vault.ErrNoActiveWallet
	}
	for _, w := range f.wallets {
		if w.ID == f.activeID {
			return w, nil
		}
	}
	return vault.WalletMeta{}, vault.ErrNoActiveWallet
}

// fakeSettings is an in-memory SettingsController for handler tests.
type fakeSettings struct {
	enabled         bool
	restartRequired bool
	setErr          error
	setCalledWith   bool
	setCalled       bool

	autoLockMinutes       int
	setAutoLockErr        error
	setAutoLockCalled     bool
	setAutoLockCalledWith int
}

func (f *fakeSettings) HistoryExpiry() bool { return f.enabled }

func (f *fakeSettings) SetHistoryExpiry(enabled bool) error {
	f.setCalled = true
	f.setCalledWith = enabled
	if f.setErr != nil {
		return f.setErr
	}
	f.enabled = enabled
	return nil
}

func (f *fakeSettings) HistoryExpiryRestartRequired() bool { return f.restartRequired }

func (f *fakeSettings) AutoLockMinutes() int { return f.autoLockMinutes }

func (f *fakeSettings) SetAutoLockMinutes(minutes int) error {
	f.setAutoLockCalled = true
	f.setAutoLockCalledWith = minutes
	if f.setAutoLockErr != nil {
		return f.setAutoLockErr
	}
	f.autoLockMinutes = minutes
	return nil
}

// fakeContacts is an in-memory Contacts controller for handler tests. It
// mimics the real store's API semantics enough to exercise the API layer
// without touching disk.
type fakeContacts struct {
	entries   []contacts.Entry
	upsertErr error
	deleteErr error
	nextID    int
}

func (f *fakeContacts) List() []contacts.Entry {
	out := make([]contacts.Entry, len(f.entries))
	copy(out, f.entries)
	return out
}

func (f *fakeContacts) Upsert(in contacts.Entry) (contacts.Entry, error) {
	if f.upsertErr != nil {
		return contacts.Entry{}, f.upsertErr
	}
	if in.Name == "" {
		return contacts.Entry{}, fmt.Errorf("%w: name is required", contacts.ErrInvalidRequest)
	}
	if in.Address == "" {
		return contacts.Entry{}, fmt.Errorf("%w: address is required", contacts.ErrInvalidRequest)
	}
	if in.ID == "" {
		f.nextID++
		in.ID = fmt.Sprintf("c%d", f.nextID)
		f.entries = append(f.entries, in)
		return in, nil
	}
	for i, e := range f.entries {
		if e.ID == in.ID {
			f.entries[i] = in
			return in, nil
		}
	}
	return contacts.Entry{}, fmt.Errorf("%w: %s", contacts.ErrNotFound, in.ID)
}

func (f *fakeContacts) Delete(id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for i, e := range f.entries {
		if e.ID == id {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: %s", contacts.ErrNotFound, id)
}

func (f *fakeVault) TPMStatus() vault.TPMStatusInfo { return f.tpmStatus }

func (f *fakeVault) EnableTPM(password string, pcrBound bool) error {
	f.enableTPMCalled = true
	f.enableTPMPassword = password
	f.enableTPMPCRBound = pcrBound
	return f.enableTPMErr
}

func (f *fakeVault) DisableTPM(password string) error {
	f.disableTPMCalled = true
	f.disableTPMPassword = password
	return f.disableTPMErr
}

func TestHealthAlwaysOK(t *testing.T) {
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health = %d, want 200", rec.Code)
	}
}

func TestStatusReturnsSnapshot(t *testing.T) {
	want := supervisor.Status{State: supervisor.StateSyncing, Tip: 42, CaughtUp: true}
	h := NewHandler(fakeStatuser{s: want}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/status = %d, want 200", rec.Code)
	}
	var got supervisor.Status
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.State != want.State || got.Tip != want.Tip || got.CaughtUp != want.CaughtUp {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// fakeWallet is stateful like the real service: queries return wallet.ErrNoWallet
// until SetAccount has been called (the vault pushes the active account).
type fakeWallet struct {
	balance          wallet.Balance
	set              bool
	setAccountCalled bool
	gotNetwork       string
	txDetail         wallet.TxDetail
	txDetailErr      error
}

func (f *fakeWallet) SetAccount(acct *wallet.Account) error {
	if acct == nil {
		f.set = false
		f.setAccountCalled = true
		f.gotNetwork = ""
		return nil
	}
	f.set = true
	f.setAccountCalled = true
	f.gotNetwork = acct.Network
	return nil
}

func (f *fakeWallet) Balance(_ context.Context) (wallet.Balance, error) {
	if !f.set {
		return wallet.Balance{}, wallet.ErrNoWallet
	}
	return f.balance, nil
}

func (f *fakeWallet) Addresses(_ context.Context) (wallet.AddressView, error) {
	if !f.set {
		return wallet.AddressView{}, wallet.ErrNoWallet
	}
	return wallet.AddressView{}, nil
}

func (f *fakeWallet) Transactions(_ context.Context) ([]wallet.Tx, error) {
	if !f.set {
		return nil, wallet.ErrNoWallet
	}
	return nil, nil
}

func (f *fakeWallet) TransactionDetail(_ context.Context, hash string) (wallet.TxDetail, error) {
	if !f.set {
		return wallet.TxDetail{}, wallet.ErrNoWallet
	}
	if f.txDetailErr != nil {
		return wallet.TxDetail{}, f.txDetailErr
	}
	if f.txDetail.TxHash != "" {
		return f.txDetail, nil
	}
	return wallet.TxDetail{Tx: wallet.Tx{TxHash: hash}}, nil
}

func (f *fakeWallet) Delegation(_ context.Context) (wallet.DelegationView, error) {
	if !f.set {
		return wallet.DelegationView{}, wallet.ErrNoWallet
	}
	return wallet.DelegationView{}, nil
}

// --- Vault lifecycle --------------------------------------------------------

func TestVaultStatusReports(t *testing.T) {
	fv := &fakeVault{exists: true, locked: true, wallets: []vault.WalletMeta{{ID: "a"}, {ID: "b"}}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vault/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vault/status = %d, want 200", rec.Code)
	}
	var got vaultStatus
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Exists || !got.Locked || got.WalletCount != 2 {
		t.Fatalf("status = %+v, want exists/locked/count=2", got)
	}
	if got.LegacyKeystore {
		t.Fatal("legacy keystore should not be advertised when a vault exists")
	}
}

func TestVaultStatusReportsLegacyKeystore(t *testing.T) {
	fv := &fakeVault{exists: false, locked: true}
	legacy := &fakeLegacyKeystore{exists: true}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler(), WithLegacyKeystore(legacy))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vault/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vault/status = %d, want 200", rec.Code)
	}
	var got vaultStatus
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Exists || !got.LegacyKeystore {
		t.Fatalf("status = %+v, want no vault and legacy_keystore=true", got)
	}
}

func TestVaultCreateRequiresPassword(t *testing.T) {
	fv := &fakeVault{}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault", bytes.NewBufferString(`{"password":"short"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /vault short password = %d, want 400", rec.Code)
	}
	if fv.exists {
		t.Fatal("vault should not be created with a too-short password")
	}
}

func TestVaultCreateOK(t *testing.T) {
	fv := &fakeVault{}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault", bytes.NewBufferString(`{"password":"valid-vault-password"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault = %d, want 200", rec.Code)
	}
	if !fv.exists {
		t.Fatal("vault should exist after create")
	}
}

func TestVaultCreateConflict(t *testing.T) {
	fv := &fakeVault{createErr: vault.ErrVaultExists}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault", bytes.NewBufferString(`{"password":"valid-vault-password"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /vault when exists = %d, want 409", rec.Code)
	}
}

func TestVaultUnlockBindsSoleWalletAndReads(t *testing.T) {
	// A single-wallet vault auto-activates on unlock; reads then succeed.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fv := &fakeVault{
		exists:  true,
		locked:  true,
		wallets: []vault.WalletMeta{{ID: "w1", Name: "main", Network: "preview", Account: sampleAccount("preview")}},
	}
	fw := &fakeWallet{balance: wallet.Balance{Lovelace: "1234"}}
	h := NewHandler(st, fv, fw, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/unlock", bytes.NewBufferString(`{"password":"valid-vault-password"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault/unlock = %d, want 200", rec.Code)
	}
	var list []walletView
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 || !list[0].Active {
		t.Fatalf("unlock list = %+v, want one active wallet", list)
	}
	if !fw.setAccountCalled {
		t.Fatal("sole wallet should be bound to the read service on unlock")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/balance after unlock = %d, want 200", rec.Code)
	}
}

func TestVaultUnlockWrongPassword(t *testing.T) {
	fv := &fakeVault{exists: true, locked: true, unlockErr: fmt.Errorf("%w: bad", vault.ErrWrongPassword)}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/unlock", bytes.NewBufferString(`{"password":"wrong-but-long-pw"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /vault/unlock wrong password = %d, want 401", rec.Code)
	}
}

func TestVaultLock(t *testing.T) {
	fv := &fakeVault{exists: true, locked: false}
	fw := &fakeWallet{set: true}
	sp := &fakeSpender{set: true}
	h := NewHandler(fakeStatuser{}, fv, fw, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/lock", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault/lock = %d, want 200", rec.Code)
	}
	if !fv.locked {
		t.Fatal("vault should be locked after POST /vault/lock")
	}
	if fw.set || sp.set {
		t.Fatal("vault lock should clear read and spend service bindings")
	}
}

func TestMigrateLegacyKeystoreImportsAndBinds(t *testing.T) {
	fv := &fakeVault{exists: false, locked: true}
	fw := &fakeWallet{}
	sp := &fakeSpender{}
	legacy := &fakeLegacyKeystore{exists: true, mnemonic: []byte("abandon abandon about")}
	h := NewHandler(fakeStatuser{}, fv, fw, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler(), WithLegacyKeystore(legacy))

	body := `{"name":"Imported","vault_password":"valid-vault-password","spend_password":"legacy-spend-password"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/migrate-legacy", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault/migrate-legacy = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !fv.imported || fv.gotName != "Imported" || fv.gotVault != "valid-vault-password" || fv.gotSpend != "legacy-spend-password" {
		t.Fatalf("legacy import not called as expected: %+v", fv)
	}
	if legacy.gotPw != "legacy-spend-password" {
		t.Fatalf("legacy unlock password = %q", legacy.gotPw)
	}
	for i, b := range legacy.returned {
		if b != 0 {
			t.Fatalf("legacy mnemonic byte %d not zeroed after import", i)
		}
	}
	for i, b := range fv.gotSeed {
		if b != 0 {
			t.Fatalf("imported mnemonic byte %d not zeroed after import", i)
		}
	}
	if !fw.set || !sp.set || sp.gotID != "legacy1" {
		t.Fatalf("imported wallet should be bound: wallet set=%v spend set=%v id=%q", fw.set, sp.set, sp.gotID)
	}
	var got walletView
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "legacy1" || !got.Active {
		t.Fatalf("migration response = %+v, want active legacy wallet", got)
	}
}

func TestMigrateLegacyKeystoreWrongPassword(t *testing.T) {
	fv := &fakeVault{exists: false, locked: true}
	legacy := &fakeLegacyKeystore{exists: true, err: keystore.ErrDecryptFailed}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler(), WithLegacyKeystore(legacy))

	body := `{"name":"Imported","vault_password":"valid-vault-password","spend_password":"wrong-password"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/migrate-legacy", bytes.NewBufferString(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong legacy password = %d, want 401", rec.Code)
	}
	if fv.imported || fv.exists {
		t.Fatal("wrong legacy password should not create a vault")
	}
}

func TestMigrateLegacyKeystoreRequiresSpendPasswordMinLength(t *testing.T) {
	fv := &fakeVault{exists: false, locked: true}
	legacy := &fakeLegacyKeystore{exists: true, mnemonic: []byte("abandon abandon about")}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler(), WithLegacyKeystore(legacy))

	body := `{"name":"Imported","vault_password":"valid-vault-password","spend_password":"short"}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/migrate-legacy", bytes.NewBufferString(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short legacy spend password = %d, want 400", rec.Code)
	}
	if legacy.gotPw != "" {
		t.Fatalf("legacy keystore should not be unlocked with a too-short password, got %q", legacy.gotPw)
	}
	if fv.imported || fv.exists {
		t.Fatal("short legacy spend password should not create a vault")
	}
}

// --- Wallet management ------------------------------------------------------

func TestAddWalletEnablesReadsAndSpend(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fv := &fakeVault{exists: true, locked: false}
	fw := &fakeWallet{balance: wallet.Balance{Lovelace: "1234"}}
	sp := &fakeSpender{}
	h := NewHandler(st, fv, fw, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := `{"name":"main","mnemonic":"x x x","network":"preview","vault_password":"valid-vault-password","spend_password":"valid-spend-password"}`
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet = %d, want 200", rec.Code)
	}
	if !fv.addCalled || fv.gotName != "main" || fv.gotSpend != "valid-spend-password" || fv.gotVault != "valid-vault-password" {
		t.Fatalf("AddWallet not called as expected: %+v", fv)
	}
	if !fw.setAccountCalled {
		t.Fatal("added wallet should be bound to the read service")
	}
	if !sp.setAccountCalled {
		t.Fatal("added wallet should be bound to the spend service")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/balance after add = %d, want 200", rec.Code)
	}
}

func TestAddWalletRequiresSpendPassword(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fv := &fakeVault{exists: true, locked: false}
	sp := &fakeSpender{}
	h := NewHandler(st, fv, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := `{"name":"main","mnemonic":"x x x","network":"preview","vault_password":"valid-vault-password","spend_password":"short"}`
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", bytes.NewBufferString(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet short spend password = %d, want 400", rec.Code)
	}
	if fv.addCalled {
		t.Fatal("AddWallet should not be called with a too-short spend password")
	}
}

func TestAddWalletRequiresVaultPassword(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fv := &fakeVault{exists: true, locked: false}
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := `{"name":"main","mnemonic":"x x x","network":"preview","spend_password":"valid-spend-password"}`
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", bytes.NewBufferString(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet missing vault password = %d, want 400", rec.Code)
	}
}

func TestAddWalletNetworkMismatch(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fv := &fakeVault{exists: true, locked: false}
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := `{"name":"main","mnemonic":"x x x","network":"mainnet","vault_password":"valid-vault-password","spend_password":"valid-spend-password"}`
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", bytes.NewBufferString(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet network mismatch = %d, want 400", rec.Code)
	}
}

func TestAddWalletDefaultNetworkIsNodeNetwork(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fv := &fakeVault{exists: true, locked: false}
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preprod", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := `{"name":"main","mnemonic":"x x x","vault_password":"valid-vault-password","spend_password":"valid-spend-password"}`
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet without network = %d, want 200", rec.Code)
	}
	if fv.gotNetwork != "preprod" {
		t.Fatalf("AddWallet got network %q, want preprod (node network)", fv.gotNetwork)
	}
}

func TestAddWalletDuplicateConflict(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fv := &fakeVault{exists: true, locked: false, addErr: vault.ErrDuplicateWallet}
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := `{"name":"main","mnemonic":"x x x","network":"preview","vault_password":"valid-vault-password","spend_password":"valid-spend-password"}`
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", bytes.NewBufferString(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /wallet duplicate = %d, want 409", rec.Code)
	}
}

// TestGenerateMnemonic asserts the generate endpoint returns a non-empty
// mnemonic (24-word / 256-bit BIP39). It does not need a vault or a node —
// the endpoint is ungated and uses only the bursa core lib.
func TestGenerateMnemonic(t *testing.T) {
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/mnemonic/generate", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/mnemonic/generate = %d, want 200", rec.Code)
	}
	var body struct {
		Mnemonic string `json:"mnemonic"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Mnemonic == "" {
		t.Fatal("expected non-empty mnemonic")
	}
	words := strings.Fields(body.Mnemonic)
	if len(words) != 24 {
		t.Fatalf("expected 24-word mnemonic, got %d words", len(words))
	}
}

func TestActivateWalletBinds(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fv := &fakeVault{
		exists: true, locked: false,
		wallets: []vault.WalletMeta{
			{ID: "w1", Name: "one", Network: "preview", Account: sampleAccount("preview")},
			{ID: "w2", Name: "two", Network: "preview", Account: sampleAccount("preview")},
		},
	}
	fw := &fakeWallet{}
	sp := &fakeSpender{}
	h := NewHandler(st, fv, fw, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/w2/activate", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/w2/activate = %d, want 200", rec.Code)
	}
	if fv.activeID != "w2" {
		t.Fatalf("active = %q, want w2", fv.activeID)
	}
	if !fw.setAccountCalled || !sp.setAccountCalled {
		t.Fatal("activate should bind the wallet to both services")
	}
	var got walletView
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "w2" || !got.Active {
		t.Fatalf("activate response = %+v, want active w2", got)
	}
}

func TestActivateUnknownWallet(t *testing.T) {
	fv := &fakeVault{exists: true, locked: false}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/nope/activate", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("activate unknown = %d, want 404", rec.Code)
	}
}

func TestDeleteWalletRequiresVaultPassword(t *testing.T) {
	fv := &fakeVault{exists: true, locked: false, wallets: []vault.WalletMeta{{ID: "w1"}}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/wallet/w1", bytes.NewBufferString(`{}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("DELETE /wallet/w1 without vault password = %d, want 400", rec.Code)
	}
}

func TestDeleteWalletOK(t *testing.T) {
	fv := &fakeVault{
		exists: true, locked: false, activeID: "w1",
		wallets: []vault.WalletMeta{{ID: "w1", Account: sampleAccount("preview")}},
	}
	fw := &fakeWallet{set: true}
	sp := &fakeSpender{set: true}
	h := NewHandler(fakeStatuser{}, fv, fw, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/wallet/w1", bytes.NewBufferString(`{"vault_password":"valid-vault-password"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /wallet/w1 = %d, want 200", rec.Code)
	}
	if len(fv.wallets) != 0 {
		t.Fatalf("wallet not removed: %+v", fv.wallets)
	}
	if fw.set || sp.set {
		t.Fatal("deleting the active wallet should clear stale service bindings")
	}
}

// --- Read gating ------------------------------------------------------------

func TestWalletGatedWhileStarting(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/balance while starting = %d, want 503", rec.Code)
	}
}

func TestWalletGatedWhileBootstrapping(t *testing.T) {
	// Mithril bootstrap is not a servable state: reads must be gated (503).
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateBootstrapping}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/balance while bootstrapping = %d, want 503", rec.Code)
	}
}

func TestWalletNoActiveWalletConflict(t *testing.T) {
	// No active wallet bound: reads must yield 409 (the read service has no account).
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	for _, path := range []string{"/wallet/balance", "/wallet/addresses", "/wallet/transactions", "/wallet/transactions/tx1", "/wallet/delegation"} {
		t.Run(path, func(t *testing.T) {
			h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusConflict {
				t.Fatalf("GET %s with no active wallet = %d, want 409", path, rec.Code)
			}
		})
	}
}

func TestGetTransactionDetailOK(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fw := &fakeWallet{
		set: true,
		txDetail: wallet.TxDetail{
			Tx: wallet.Tx{
				TxHash:      "tx1",
				Direction:   wallet.TxDirectionSent,
				NetLovelace: "-3170000",
				Fee:         "170000",
			},
			Inputs:  []wallet.TxIO{{Address: "addr_mine", Lovelace: "5000000", IsMine: true}},
			Outputs: []wallet.TxIO{{Address: "addr_other", Lovelace: "3000000"}},
		},
	}
	h := NewHandler(st, &fakeVault{}, fw, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/transactions/tx1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/transactions/tx1 = %d, want 200", rec.Code)
	}
	var got wallet.TxDetail
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TxHash != "tx1" || got.Direction != wallet.TxDirectionSent || got.Fee != "170000" {
		t.Fatalf("detail = %+v, want tx1/sent/170000 fee", got)
	}
	if len(got.Inputs) != 1 || !got.Inputs[0].IsMine || len(got.Outputs) != 1 {
		t.Fatalf("inputs/outputs = %+v / %+v", got.Inputs, got.Outputs)
	}
}

func TestGetTransactionDetailNotFound(t *testing.T) {
	// The node has no record of the hash: surfaced as 404, matching the
	// pool/DRep lookup convention ("not found by your node").
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fw := &fakeWallet{set: true, txDetailErr: chain.ErrNotFound}
	h := NewHandler(st, &fakeVault{}, fw, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/transactions/unknown", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /wallet/transactions/unknown = %d, want 404", rec.Code)
	}
}

// --- Spending ---------------------------------------------------------------

// fakeSpender implements the api.Spender interface for handler tests.
type fakeSpender struct {
	buildErr         error
	confirmErr       error
	preview          spend.Preview
	result           spend.TxResult
	setAccountCalled bool
	set              bool
	gotID            string
	confirmID        string
	signSig          string
	signKey          string
	signErr          error
	signAddr         string

	// verify-data
	verifyValid   bool
	verifyAddr    string
	verifyErr     error
	gotVerifySig  string
	gotVerifyKey  string
	gotVerifyMsg  string
	gotVerifyExp  string
	gotVerifyHash bool

	// air-gap
	unsigned      spend.UnsignedTx
	exportErr     error
	gotExportID   string
	witness       spend.Witness
	signTxErr     error
	gotSignTxCBOR string
	gotSignTxPass string
	gotSignTxReq  []string
	submitResult  spend.TxResult
	submitErr     error
	gotSubmitTx   string
	gotSubmitWit  string
}

func (f *fakeSpender) SetAccount(id string, acct *wallet.Account) {
	f.setAccountCalled = true
	f.gotID = id
	f.set = acct != nil
}

func (f *fakeSpender) Build(_ context.Context, _ spend.SendRequest) (spend.Preview, error) {
	if f.buildErr != nil {
		return spend.Preview{}, f.buildErr
	}
	return f.preview, nil
}

func (f *fakeSpender) Confirm(_ context.Context, pendingID, _ string) (spend.TxResult, error) {
	if f.confirmErr != nil {
		return spend.TxResult{}, f.confirmErr
	}
	f.confirmID = pendingID
	return f.result, nil
}

func (f *fakeSpender) SignData(addr string, _ []byte, _ string) (string, string, error) {
	f.signAddr = addr
	if f.signErr != nil {
		return "", "", f.signErr
	}
	return f.signSig, f.signKey, nil
}

func (f *fakeSpender) VerifyData(sig, key string, msg []byte, hashed bool, expected string) (bool, string, error) {
	f.gotVerifySig = sig
	f.gotVerifyKey = key
	f.gotVerifyMsg = string(msg)
	f.gotVerifyExp = expected
	f.gotVerifyHash = hashed
	if f.verifyErr != nil {
		return false, "", f.verifyErr
	}
	return f.verifyValid, f.verifyAddr, nil
}

func (f *fakeSpender) ExportUnsigned(pendingID string) (spend.UnsignedTx, error) {
	f.gotExportID = pendingID
	if f.exportErr != nil {
		return spend.UnsignedTx{}, f.exportErr
	}
	return f.unsigned, nil
}

func (f *fakeSpender) SignTx(unsignedTxCBOR, password string, requiredSigners []string) (spend.Witness, error) {
	f.gotSignTxCBOR = unsignedTxCBOR
	f.gotSignTxPass = password
	f.gotSignTxReq = append([]string(nil), requiredSigners...)
	if f.signTxErr != nil {
		return spend.Witness{}, f.signTxErr
	}
	return f.witness, nil
}

func (f *fakeSpender) SubmitSigned(_ context.Context, unsignedTxCBOR, witnessCBOR string) (spend.TxResult, error) {
	f.gotSubmitTx = unsignedTxCBOR
	f.gotSubmitWit = witnessCBOR
	if f.submitErr != nil {
		return spend.TxResult{}, f.submitErr
	}
	return f.submitResult, nil
}

func (f *fakeSpender) BuildDelegation(_ context.Context, _ spend.DelegationRequest) (spend.DelegationPreview, error) {
	if f.buildErr != nil {
		return spend.DelegationPreview{}, f.buildErr
	}
	return spend.DelegationPreview{}, nil
}

// fakePoolOps implements the api.PoolOps interface for handler tests. Each
// method returns a canned value or a configured error so the handler routing,
// gating, and error-code mapping can be exercised without real key derivation.
type fakePoolOps struct {
	setAccountCalled bool
	credErr          error
	kesErr           error
	opcertErr        error
	metadataErr      error
	idErr            error
	regErr           error
	retireErr        error
	submitErr        error

	creds     poolops.Credentials
	kes       poolops.KESPeriodInfo
	opcert    poolops.OpCert
	payload   poolops.OpCertPayload
	metadata  poolops.MetadataResult
	cert      poolops.CertResult
	tx        poolops.TxResult
	poolID    string
	poolIDHex string

	credPassword     string
	issuePassword    string
	issueKESIndex    uint32
	issueNumber      uint64
	issueKESPeriod   uint64
	rotatePassword   string
	rotateKESIndex   uint32
	rotatePrevIssue  uint64
	rotateKESPeriod  uint64
	payloadKESVKey   string
	payloadIssue     uint64
	payloadKESPeriod uint64
	assembleColdVKey string
	assembleKESVKey  string
	assembleSig      string
	assembleIssue    uint64
	assemblePeriod   uint64
	metadataInput    poolops.MetadataInput
	idColdVKey       string
	regPassword      string
	regParams        poolops.RegistrationParams
	airGapParams     poolops.AirGapRegistrationParams
	retirePassword   string
	retireColdVKey   string
	retireEpoch      uint64
	submitPassword   string
	submitEpoch      uint64
}

func (f *fakePoolOps) SetAccount(_ string, _ *wallet.Account) { f.setAccountCalled = true }

func (f *fakePoolOps) Credentials(password string) (poolops.Credentials, error) {
	f.credPassword = password
	return f.creds, f.credErr
}

func (f *fakePoolOps) KESPeriod(_ context.Context) (poolops.KESPeriodInfo, error) {
	return f.kes, f.kesErr
}

func (f *fakePoolOps) IssueOpCert(password string, kesIndex uint32, issueNumber, kesPeriod uint64) (poolops.OpCert, error) {
	f.issuePassword = password
	f.issueKESIndex = kesIndex
	f.issueNumber = issueNumber
	f.issueKESPeriod = kesPeriod
	return f.opcert, f.opcertErr
}

func (f *fakePoolOps) RotateKES(password string, newKESIndex uint32, prevIssueNumber, kesPeriod uint64) (poolops.OpCert, error) {
	f.rotatePassword = password
	f.rotateKESIndex = newKESIndex
	f.rotatePrevIssue = prevIssueNumber
	f.rotateKESPeriod = kesPeriod
	return f.opcert, f.opcertErr
}

func (f *fakePoolOps) OpCertPayload(kesVKeyHex string, issueNumber, kesPeriod uint64) (poolops.OpCertPayload, error) {
	f.payloadKESVKey = kesVKeyHex
	f.payloadIssue = issueNumber
	f.payloadKESPeriod = kesPeriod
	return f.payload, f.opcertErr
}

func (f *fakePoolOps) AssembleOpCert(coldVKeyHex, kesVKeyHex, signatureHex string, issueNumber, kesPeriod uint64) (poolops.OpCert, error) {
	f.assembleColdVKey = coldVKeyHex
	f.assembleKESVKey = kesVKeyHex
	f.assembleSig = signatureHex
	f.assembleIssue = issueNumber
	f.assemblePeriod = kesPeriod
	return f.opcert, f.opcertErr
}

func (f *fakePoolOps) BuildMetadata(in poolops.MetadataInput) (poolops.MetadataResult, error) {
	f.metadataInput = in
	return f.metadata, f.metadataErr
}

func (f *fakePoolOps) PoolIDFromColdVKey(coldVKeyHex string) (string, string, error) {
	f.idColdVKey = coldVKeyHex
	return f.poolID, f.poolIDHex, f.idErr
}

func (f *fakePoolOps) BuildRegistrationFromSeed(password string, p poolops.RegistrationParams) (poolops.CertResult, error) {
	f.regPassword = password
	f.regParams = p
	return f.cert, f.regErr
}

func (f *fakePoolOps) BuildRegistrationAirGap(p poolops.AirGapRegistrationParams) (poolops.CertResult, error) {
	f.airGapParams = p
	return f.cert, f.regErr
}

func (f *fakePoolOps) BuildRetirementCert(password, coldVKeyHex string, epoch uint64) (poolops.CertResult, error) {
	f.retirePassword = password
	f.retireColdVKey = coldVKeyHex
	f.retireEpoch = epoch
	return f.cert, f.retireErr
}

func (f *fakePoolOps) SubmitRetirement(_ context.Context, password string, epoch uint64) (poolops.TxResult, error) {
	f.submitPassword = password
	f.submitEpoch = epoch
	return f.tx, f.submitErr
}

// fakeDexQuoter implements api.DexQuoter for tests. It records the arguments
// passed to Quote so tests can assert the request body was parsed correctly.
type fakeDexQuoter struct {
	pools    []dex.Pool
	poolsErr error

	quote       dex.Quote
	quoteErr    error
	gotAssetIn  string
	gotAssetOut string
	gotAmountIn uint64
}

func (f *fakeDexQuoter) Pools(_ context.Context) ([]dex.Pool, error) {
	return f.pools, f.poolsErr
}

func (f *fakeDexQuoter) Quote(_ context.Context, assetIn, assetOut string, amountIn uint64) (dex.Quote, error) {
	f.gotAssetIn = assetIn
	f.gotAssetOut = assetOut
	f.gotAmountIn = amountIn
	return f.quote, f.quoteErr
}

func TestSignDataReturnsSignature(t *testing.T) {
	// Ungated: message signing needs no synced node, only the keystore.
	sp := &fakeSpender{signSig: "84a1deadbeef", signKey: "a4010103"}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"address":"addr_test1xyz","message":"hello","password":"pw"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-data", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/sign-data = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "84a1deadbeef") || !strings.Contains(rec.Body.String(), "a4010103") {
		t.Fatalf("response missing signature/key: %s", rec.Body.String())
	}
	if sp.signAddr != "addr_test1xyz" {
		t.Fatalf("address not passed through: %q", sp.signAddr)
	}
}

func TestSignDataWrongPasswordReturns401(t *testing.T) {
	sp := &fakeSpender{signErr: fmt.Errorf("%w: bad", spend.ErrWrongPassword)}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"address":"a","message":"m","password":"bad"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-data", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-data with wrong password = %d, want 401", rec.Code)
	}
}

func TestVerifyDataReturnsResult(t *testing.T) {
	// Ungated: verification is pure crypto, needs no node and no keystore.
	sp := &fakeSpender{verifyValid: true, verifyAddr: "addr_test1signed"}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"signature":"84a1","key":"a401","message":"hi","hashed":true,"expected_address":"addr_test1signed"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/verify-data", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/verify-data = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"valid":true`) ||
		!strings.Contains(rec.Body.String(), "addr_test1signed") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if sp.gotVerifySig != "84a1" ||
		sp.gotVerifyKey != "a401" ||
		sp.gotVerifyMsg != "hi" ||
		!sp.gotVerifyHash ||
		sp.gotVerifyExp != "addr_test1signed" {
		t.Fatalf("args not passed through: %+v", sp)
	}
}

func TestVerifyDataInvalidArgsReturns400(t *testing.T) {
	sp := &fakeSpender{verifyErr: fmt.Errorf("%w: bad hex", spend.ErrInvalidRequest)}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"signature":"zz","key":"a4","message":"hi"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/verify-data", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("verify-data with bad input = %d, want 400", rec.Code)
	}
}

func TestExportUnsignedRequiresReady(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send/pend1/export-unsigned", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("export-unsigned while syncing = %d, want 503", rec.Code)
	}
}

func TestExportUnsignedReturnsTx(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{unsigned: spend.UnsignedTx{
		UnsignedTxCBOR:  "84a400",
		RequiredSigners: []string{"deadbeef"},
	}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send/pend1/export-unsigned", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export-unsigned = %d, want 200", rec.Code)
	}
	if sp.gotExportID != "pend1" {
		t.Fatalf("pending id not passed through: %q", sp.gotExportID)
	}
	if !strings.Contains(rec.Body.String(), "84a400") || !strings.Contains(rec.Body.String(), "deadbeef") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestSignTxUngated(t *testing.T) {
	// Offline signing must not need a synced node -- only the keystore.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	sp := &fakeSpender{witness: spend.Witness{WitnessCBOR: "81825820"}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","password":"pw","required_signers":["deadbeef"]}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-tx", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/sign-tx = %d, want 200", rec.Code)
	}
	if sp.gotSignTxCBOR != "84a400" ||
		sp.gotSignTxPass != "pw" ||
		len(sp.gotSignTxReq) != 1 ||
		sp.gotSignTxReq[0] != "deadbeef" {
		t.Fatalf("args not passed through: %+v", sp)
	}
	if !strings.Contains(rec.Body.String(), "81825820") {
		t.Fatalf("witness missing from body: %s", rec.Body.String())
	}
}

func TestSignTxWrongPasswordReturns401(t *testing.T) {
	sp := &fakeSpender{signTxErr: fmt.Errorf("%w: bad", spend.ErrWrongPassword)}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","password":"bad","required_signers":["deadbeef"]}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-tx", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-tx wrong password = %d, want 401", rec.Code)
	}
}

func TestSignTxInvalidTxReturns400(t *testing.T) {
	sp := &fakeSpender{signTxErr: fmt.Errorf("%w: bad cbor", spend.ErrInvalidTx)}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"zz","password":"pw","required_signers":["deadbeef"]}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-tx", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sign-tx invalid tx = %d, want 400", rec.Code)
	}
}

func TestSubmitSignedRequiresReady(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","witness_cbor":"81"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/submit-signed", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("submit-signed while syncing = %d, want 503", rec.Code)
	}
}

func TestSubmitSignedReturnsTxHash(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{submitResult: spend.TxResult{TxHash: "cafebabe"}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","witness_cbor":"81825820"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/submit-signed", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("submit-signed = %d, want 200", rec.Code)
	}
	if sp.gotSubmitTx != "84a400" || sp.gotSubmitWit != "81825820" {
		t.Fatalf("args not passed through: tx=%q wit=%q", sp.gotSubmitTx, sp.gotSubmitWit)
	}
	if !strings.Contains(rec.Body.String(), "cafebabe") {
		t.Fatalf("tx hash missing: %s", rec.Body.String())
	}
}

func TestSubmitSignedInvalidWitnessReturns400(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{submitErr: fmt.Errorf("%w: bad cbor", spend.ErrInvalidWitness)}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","witness_cbor":"zz"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/submit-signed", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("submit-signed bad witness = %d, want 400", rec.Code)
	}
}

func TestSpendSendReadyReturnsPreview(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{preview: spend.Preview{PendingID: "pend123", Fee: "170000"}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":"1000000"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/send while ready = %d, want 200", rec.Code)
	}
	var pv spend.Preview
	if err := json.NewDecoder(rec.Body).Decode(&pv); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pv.PendingID != "pend123" {
		t.Fatalf("pending_id = %q, want pend123", pv.PendingID)
	}
}

func TestSpendSendGatedWhileSyncing(t *testing.T) {
	// Spending requires a fully synced node (StateReady), unlike reads.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":"1000000"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /wallet/send while syncing = %d, want 503", rec.Code)
	}
}

func TestSpendSendNoWalletConflict(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{buildErr: spend.ErrNoWallet}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":"1000000"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send", body))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /wallet/send with no wallet = %d, want 409", rec.Code)
	}
}

func TestSpendConfirmReadyReturnsTxHash(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{result: spend.TxResult{TxHash: "deadbeef"}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"valid-spend-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send/pend123/confirm", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST confirm while ready = %d, want 200", rec.Code)
	}
	var res spend.TxResult
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.TxHash != "deadbeef" {
		t.Fatalf("tx_hash = %q, want deadbeef", res.TxHash)
	}
	if sp.confirmID != "pend123" {
		t.Fatalf("Confirm got id %q, want pend123", sp.confirmID)
	}
}

func TestSpendConfirmGatedWhileSyncing(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"valid-spend-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send/pend123/confirm", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST confirm while syncing = %d, want 503", rec.Code)
	}
}

// TestSpendErrorStatusCodes checks the spend sentinel errors map to their
// precise HTTP status codes (the spec's error table).
func TestSpendErrorStatusCodes(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	cases := []struct {
		name     string
		confirm  bool // true → exercise /confirm, false → /send
		err      error
		wantCode int
	}{
		{"invalid request", false, spend.ErrInvalidRequest, http.StatusBadRequest},
		{"insufficient funds", false, spend.ErrInsufficientFunds, http.StatusUnprocessableEntity},
		{"no wallet", false, spend.ErrNoWallet, http.StatusConflict},
		{"wrong password", true, spend.ErrWrongPassword, http.StatusUnauthorized},
		{"unknown pending", true, spend.ErrUnknownPending, http.StatusNotFound},
		{"expired pending", true, spend.ErrExpiredPending, http.StatusGone},
		{"submit rejected", true, spend.ErrSubmitRejected, http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := &fakeSpender{}
			var req *http.Request
			if tc.confirm {
				sp.confirmErr = tc.err
				req = httptest.NewRequest(http.MethodPost, "/wallet/send/pend123/confirm",
					bytes.NewBufferString(`{"password":"valid-spend-password"}`))
			} else {
				sp.buildErr = tc.err
				req = httptest.NewRequest(http.MethodPost, "/wallet/send",
					bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":"1000000"}`))
			}
			h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("%s: code = %d, want %d", tc.name, rec.Code, tc.wantCode)
			}
		})
	}
}

type historyExpiryResponse struct {
	Enabled         bool
	RestartRequired bool
}

// decodeHistoryExpiry decodes the {enabled, restart_required} body.
func decodeHistoryExpiry(t *testing.T, body *bytes.Buffer) historyExpiryResponse {
	t.Helper()
	var got struct {
		Enabled         *bool `json:"enabled"`
		RestartRequired *bool `json:"restart_required"`
	}
	if err := json.NewDecoder(body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Enabled == nil {
		t.Fatal("response missing enabled")
	}
	if got.RestartRequired == nil {
		t.Fatal("response missing restart_required")
	}
	return historyExpiryResponse{
		Enabled:         *got.Enabled,
		RestartRequired: *got.RestartRequired,
	}
}

func TestGetHistoryExpiryReturnsState(t *testing.T) {
	// Ungated: a stopped node must still answer (it is a config setting, not a
	// node query).
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStopped}}
	set := &fakeSettings{enabled: true, restartRequired: true}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/settings/history-expiry", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET history-expiry = %d, want 200", rec.Code)
	}
	got := decodeHistoryExpiry(t, rec.Body)
	if !got.Enabled || !got.RestartRequired {
		t.Fatalf("got %+v, want enabled+restart_required true", got)
	}
}

func TestGetHistoryExpiryDefaultOff(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{} // default off, no restart needed
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/settings/history-expiry", nil))
	got := decodeHistoryExpiry(t, rec.Body)
	if got.Enabled || got.RestartRequired {
		t.Fatalf("got %+v, want both false (default)", got)
	}
}

func TestPutHistoryExpiryPersistsAndSignalsRestart(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	// Running node was built with off; flipping to on must signal a restart.
	set := &fakeSettings{enabled: false, restartRequired: true}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"enabled":true}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/history-expiry", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT history-expiry = %d, want 200", rec.Code)
	}
	if !set.setCalled || !set.setCalledWith {
		t.Fatalf("SetHistoryExpiry not called with true: called=%v with=%v", set.setCalled, set.setCalledWith)
	}
	got := decodeHistoryExpiry(t, rec.Body)
	if !got.Enabled {
		t.Fatalf("response enabled = %v, want true", got.Enabled)
	}
	if !got.RestartRequired {
		t.Fatalf("response restart_required = %v, want true", got.RestartRequired)
	}
}

func TestPutHistoryExpiryInvalidJSON(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{not json`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/history-expiry", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT history-expiry with bad JSON = %d, want 400", rec.Code)
	}
	if set.setCalled {
		t.Fatal("SetHistoryExpiry must not be called on a bad request body")
	}
}

func TestPutHistoryExpiryRequiresExplicitEnabled(t *testing.T) {
	for _, bodyJSON := range []string{`{}`, `{"enabled":null}`} {
		t.Run(bodyJSON, func(t *testing.T) {
			st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
			set := &fakeSettings{}
			h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			body := bytes.NewBufferString(bodyJSON)
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/history-expiry", body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PUT history-expiry with %s = %d, want 400", bodyJSON, rec.Code)
			}
			if set.setCalled {
				t.Fatal("SetHistoryExpiry must not be called without an explicit enabled value")
			}
		})
	}
}

func TestPutHistoryExpiryPersistError(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{setErr: errors.New("disk full")}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"enabled":true}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/history-expiry", body))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT history-expiry with persist error = %d, want 500", rec.Code)
	}
}

func decodeAutoLock(t *testing.T, body *bytes.Buffer) int {
	t.Helper()
	var got struct {
		Minutes *int `json:"minutes"`
	}
	if err := json.NewDecoder(body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Minutes == nil {
		t.Fatal("response missing minutes")
	}
	return *got.Minutes
}

func TestGetAutoLockReturnsPersistedValue(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStopped}}
	set := &fakeSettings{autoLockMinutes: 30}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/settings/auto-lock", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET auto-lock = %d, want 200", rec.Code)
	}
	if got := decodeAutoLock(t, rec.Body); got != 30 {
		t.Fatalf("GET auto-lock minutes = %d, want 30", got)
	}
}

func TestPutAutoLockPersists(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{autoLockMinutes: 15}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"minutes":5}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/auto-lock", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT auto-lock = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !set.setAutoLockCalled || set.setAutoLockCalledWith != 5 {
		t.Fatalf("SetAutoLockMinutes not called with 5: called=%v with=%v", set.setAutoLockCalled, set.setAutoLockCalledWith)
	}
	if got := decodeAutoLock(t, rec.Body); got != 5 {
		t.Fatalf("PUT auto-lock response minutes = %d, want 5", got)
	}
}

func TestPutAutoLockAcceptsOff(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{autoLockMinutes: 15}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"minutes":0}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/auto-lock", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT auto-lock 0 (Off) = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := decodeAutoLock(t, rec.Body); got != 0 {
		t.Fatalf("PUT auto-lock response minutes = %d, want 0", got)
	}
}

func TestPutAutoLockInvalidJSON(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{not json`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/auto-lock", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT auto-lock with bad JSON = %d, want 400", rec.Code)
	}
	if set.setAutoLockCalled {
		t.Fatal("SetAutoLockMinutes must not be called on a bad request body")
	}
}

func TestPutAutoLockRequiresExplicitMinutes(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/auto-lock", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT auto-lock with no minutes = %d, want 400", rec.Code)
	}
	if set.setAutoLockCalled {
		t.Fatal("SetAutoLockMinutes must not be called without an explicit minutes value")
	}
}

func TestPutAutoLockRejectsOutOfSetValue(t *testing.T) {
	for _, bad := range []int{-1, 2, 60} {
		st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
		set := &fakeSettings{}
		h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
		rec := httptest.NewRecorder()
		body := bytes.NewBufferString(fmt.Sprintf(`{"minutes":%d}`, bad))
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/auto-lock", body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT auto-lock with %d = %d, want 400", bad, rec.Code)
		}
		if set.setAutoLockCalled {
			t.Fatalf("SetAutoLockMinutes must not be called for out-of-set value %d", bad)
		}
	}
}

func TestPutAutoLockPersistError(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	set := &fakeSettings{setAutoLockErr: errors.New("disk full")}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"minutes":5}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/auto-lock", body))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT auto-lock with persist error = %d, want 500", rec.Code)
	}
}

// TestAutoLockOptionsMatchesSettingsPackage guards against the api-layer's
// autoLockOptions (duplicated for decoupling, see its doc comment) silently
// drifting from settings.AutoLockOptions — the two must always accept exactly
// the same set of timeouts. The frontend's AUTO_LOCK_OPTIONS
// (web/src/screens/Settings.tsx) duplicates the same set again for the <Select>
// and is guarded only by a cross-referencing comment, since it lives outside
// the Go module.
func TestAutoLockOptionsMatchesSettingsPackage(t *testing.T) {
	want := make(map[int]bool, len(settings.AutoLockOptions))
	for _, v := range settings.AutoLockOptions {
		want[v] = true
	}
	if len(autoLockOptions) != len(want) {
		t.Fatalf("autoLockOptions has %d entries, settings.AutoLockOptions has %d: %v vs %v", len(autoLockOptions), len(want), autoLockOptions, want)
	}
	for v := range want {
		if !autoLockOptions[v] {
			t.Fatalf("autoLockOptions is missing %d, present in settings.AutoLockOptions", v)
		}
	}
}

// --- Address book (local-only contacts) ---

func decodeContactEntry(t *testing.T, body *bytes.Buffer) contacts.Entry {
	t.Helper()
	var got contacts.Entry
	if err := json.Unmarshal(body.Bytes(), &got); err != nil {
		t.Fatalf("decode contact entry: %v (body=%s)", err, body.String())
	}
	return got
}

func TestContactsListReturnsEntries(t *testing.T) {
	cb := &fakeContacts{entries: []contacts.Entry{
		{ID: "c1", Name: "Alice", Address: "addr_test1alice"},
		{ID: "c2", Name: "Bob", Address: "addr_test1bob", Note: "friend"},
	}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/contacts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/contacts = %d, want 200", rec.Code)
	}
	var got []contacts.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
}

// GET /wallet/contacts must answer even while the node is stopped: it is pure
// local storage, not a node query.
func TestContactsListUngated(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStopped}}
	cb := &fakeContacts{}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/contacts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/contacts while stopped = %d, want 200", rec.Code)
	}
}

func TestContactsCreateGeneratesEntry(t *testing.T) {
	cb := &fakeContacts{}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"name":"Alice","address":"addr_test1alice","note":"friend"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/contacts", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/contacts = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeContactEntry(t, rec.Body)
	if got.ID == "" {
		t.Fatal("created contact should have a generated ID")
	}
	if got.Name != "Alice" || got.Address != "addr_test1alice" || got.Note != "friend" {
		t.Fatalf("created contact = %+v, want name/address/note echoed back", got)
	}
	if len(cb.entries) != 1 {
		t.Fatalf("fake store has %d entries, want 1", len(cb.entries))
	}
}

func TestContactsUpdateExistingByID(t *testing.T) {
	cb := &fakeContacts{entries: []contacts.Entry{{ID: "c1", Name: "Alice", Address: "addr_test1alice"}}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"id":"c1","name":"Alice Updated","address":"addr_test1alice2"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/contacts", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST update = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeContactEntry(t, rec.Body)
	if got.ID != "c1" || got.Name != "Alice Updated" || got.Address != "addr_test1alice2" {
		t.Fatalf("updated contact = %+v", got)
	}
	if len(cb.entries) != 1 {
		t.Fatalf("update must not create a duplicate entry, got %d entries", len(cb.entries))
	}
}

func TestContactsUpsertUnknownIDReturns404(t *testing.T) {
	cb := &fakeContacts{}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"id":"missing","name":"Ghost","address":"addr_test1ghost"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/contacts", body))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST with unknown id = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestContactsCreateValidationErrorReturns400(t *testing.T) {
	cb := &fakeContacts{}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"name":"","address":"addr_test1alice"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/contacts", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with blank name = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(cb.entries) != 0 {
		t.Fatal("a rejected create must not persist anything")
	}
}

func TestContactsCreateInvalidJSONReturns400(t *testing.T) {
	cb := &fakeContacts{}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{not json`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/contacts", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with bad JSON = %d, want 400", rec.Code)
	}
}

func TestContactsDeleteOK(t *testing.T) {
	cb := &fakeContacts{entries: []contacts.Entry{{ID: "c1", Name: "Alice", Address: "addr_test1alice"}}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/wallet/contacts/c1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /wallet/contacts/c1 = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(cb.entries) != 0 {
		t.Fatal("contact should have been removed")
	}
}

func TestContactsDeleteUnknownReturns404(t *testing.T) {
	cb := &fakeContacts{}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, cb, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/wallet/contacts/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE unknown id = %d, want 404", rec.Code)
	}
}

// --- Pool operations (SPO) ---

// readyStatuser returns a fully-synced node for pool ops that need a node.
func readyStatuser() fakeStatuser {
	return fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
}

func TestPoolCredentialsReturnsCreds(t *testing.T) {
	po := &fakePoolOps{creds: poolops.Credentials{PoolID: "pool1abc", Network: "preview"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"spend-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/credentials", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/pool/credentials = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pool1abc") {
		t.Fatalf("response missing pool ID: %s", rec.Body.String())
	}
	if po.credPassword != "spend-password" {
		t.Fatalf("credentials password = %q, want spend-password", po.credPassword)
	}
}

func TestPoolCredentialsRejectsTrailingJSON(t *testing.T) {
	po := &fakePoolOps{creds: poolops.Credentials{PoolID: "pool1abc", Network: "preview"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"spend-password"} {"password":"ignored"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/credentials", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("credentials with trailing JSON = %d, want 400", rec.Code)
	}
	if po.credPassword != "" {
		t.Fatalf("credentials was called despite trailing JSON: password=%q", po.credPassword)
	}
}

func TestPoolCredentialsNoWalletConflict(t *testing.T) {
	po := &fakePoolOps{credErr: poolops.ErrNoWallet}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"x"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/credentials", body))
	if rec.Code != http.StatusConflict {
		t.Fatalf("credentials with no wallet = %d, want 409", rec.Code)
	}
}

func TestPoolCredentialsWrongPassword401(t *testing.T) {
	po := &fakePoolOps{credErr: fmt.Errorf("%w: bad", poolops.ErrWrongPassword)}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"bad"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/credentials", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("credentials wrong password = %d, want 401", rec.Code)
	}
}

func TestPoolKESPeriodGatedWhileStarting(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/pool/kes-period", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("kes-period while starting = %d, want 503", rec.Code)
	}
}

func TestPoolKESPeriodReady(t *testing.T) {
	po := &fakePoolOps{kes: poolops.KESPeriodInfo{CurrentPeriod: 7, SlotsPerKESPeriod: 129600}}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/pool/kes-period", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("kes-period ready = %d, want 200", rec.Code)
	}
	var info poolops.KESPeriodInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.CurrentPeriod != 7 {
		t.Fatalf("current period = %d, want 7", info.CurrentPeriod)
	}
}

func TestPoolOpCertIssue(t *testing.T) {
	po := &fakePoolOps{opcert: poolops.OpCert{IssueNumber: 3, KesPeriod: 7, KesVKeyHex: "abcd"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","kes_index":0,"issue_number":3,"kes_period":7}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("opcert issue = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "abcd") {
		t.Fatalf("opcert response missing kes vkey: %s", rec.Body.String())
	}
	if po.issuePassword != "pw" || po.issueKESIndex != 0 || po.issueNumber != 3 || po.issueKESPeriod != 7 {
		t.Fatalf("issue args = password %q index %d issue %d period %d, want pw/0/3/7", po.issuePassword, po.issueKESIndex, po.issueNumber, po.issueKESPeriod)
	}
}

func TestPoolOpCertRotate(t *testing.T) {
	po := &fakePoolOps{opcert: poolops.OpCert{IssueNumber: 4, KESIndex: 1}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","new_kes_index":1,"prev_issue_number":3,"kes_period":7}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert/rotate", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("opcert rotate = %d, want 200", rec.Code)
	}
	var got poolops.OpCert
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode opcert rotate response: %v", err)
	}
	if got.IssueNumber != 4 || got.KESIndex != 1 {
		t.Fatalf("opcert rotate: got IssueNumber=%d KESIndex=%d, want 4/1", got.IssueNumber, got.KESIndex)
	}
	if po.rotatePassword != "pw" || po.rotateKESIndex != 1 || po.rotatePrevIssue != 3 || po.rotateKESPeriod != 7 {
		t.Fatalf("rotate args = password %q index %d prev %d period %d, want pw/1/3/7", po.rotatePassword, po.rotateKESIndex, po.rotatePrevIssue, po.rotateKESPeriod)
	}
}

func TestPoolOpCertPayloadAndAssembleAirGap(t *testing.T) {
	po := &fakePoolOps{
		payload: poolops.OpCertPayload{PayloadHex: "8203", KesVKeyHex: "ab"},
		opcert:  poolops.OpCert{IssueNumber: 1},
	}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"kes_vkey_hex":"ab","issue_number":1,"kes_period":2}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert/payload", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "8203") {
		t.Fatalf("opcert payload = %d body %s", rec.Code, rec.Body.String())
	}
	if po.payloadKESVKey != "ab" || po.payloadIssue != 1 || po.payloadKESPeriod != 2 {
		t.Fatalf("payload args = vkey %q issue %d period %d, want ab/1/2", po.payloadKESVKey, po.payloadIssue, po.payloadKESPeriod)
	}

	rec = httptest.NewRecorder()
	body = bytes.NewBufferString(`{"cold_vkey_hex":"aa","kes_vkey_hex":"bb","signature_hex":"cc","issue_number":1,"kes_period":2}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert/assemble", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("opcert assemble = %d, want 200", rec.Code)
	}
	if po.assembleColdVKey != "aa" || po.assembleKESVKey != "bb" || po.assembleSig != "cc" || po.assembleIssue != 1 || po.assemblePeriod != 2 {
		t.Fatalf("assemble args = cold %q kes %q sig %q issue %d period %d, want aa/bb/cc/1/2", po.assembleColdVKey, po.assembleKESVKey, po.assembleSig, po.assembleIssue, po.assemblePeriod)
	}
}

func TestPoolAssembleOpCertBadSignature400(t *testing.T) {
	po := &fakePoolOps{opcertErr: fmt.Errorf("%w: bad sig", poolops.ErrInvalidRequest)}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"cold_vkey_hex":"aa","kes_vkey_hex":"bb","signature_hex":"00","issue_number":1,"kes_period":2}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert/assemble", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("assemble bad sig = %d, want 400", rec.Code)
	}
}

func TestPoolMetadataBuilder(t *testing.T) {
	po := &fakePoolOps{metadata: poolops.MetadataResult{JSON: `{"name":"P"}`, HashHex: "deadbeef"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"name":"P","ticker":"POOL","homepage":"https://x","description":"d"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/metadata", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "deadbeef") {
		t.Fatalf("metadata = %d body %s", rec.Code, rec.Body.String())
	}
	want := poolops.MetadataInput{Name: "P", Ticker: "POOL", Homepage: "https://x", Description: "d"}
	if po.metadataInput != want {
		t.Fatalf("metadata input = %+v, want %+v", po.metadataInput, want)
	}
}

func TestPoolIDFromColdVKey(t *testing.T) {
	po := &fakePoolOps{poolID: "pool1xyz", poolIDHex: "abcdef1234"}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"cold_vkey_hex":"` + strings.Repeat("ab", 32) + `"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/id", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("pool id status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "pool1xyz") {
		t.Fatalf("pool id response missing bech32 pool_id: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "abcdef1234") {
		t.Fatalf("pool id response missing hex pool_id_hex: %s", rec.Body.String())
	}
	wantColdVKey := strings.Repeat("ab", 32)
	if po.idColdVKey != wantColdVKey {
		t.Fatalf("pool id cold vkey = %q, want %q", po.idColdVKey, wantColdVKey)
	}
}

func TestPoolRegistrationSeedAndAirGap(t *testing.T) {
	po := &fakePoolOps{cert: poolops.CertResult{PoolID: "pool1reg", CBORHex: "8a03"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","pledge":1,"cost":1,"margin_num":1,"margin_denom":50}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/registration", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pool1reg") {
		t.Fatalf("registration seed = %d body %s", rec.Code, rec.Body.String())
	}
	if po.regPassword != "pw" || po.regParams.Pledge != 1 || po.regParams.Cost != 1 || po.regParams.MarginNum != 1 || po.regParams.MarginDenom != 50 {
		t.Fatalf("registration seed args = password %q params %+v, want pw and pledge/cost/margin 1/1/1/50", po.regPassword, po.regParams)
	}

	rec = httptest.NewRecorder()
	body = bytes.NewBufferString(`{"cold_vkey_hex":"ab","vrf_key_hash_hex":"cd","pledge":1,"cost":1,"margin_num":0,"margin_denom":1}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/registration/airgap", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("registration airgap = %d, want 200", rec.Code)
	}
	if po.airGapParams.ColdVKeyHex != "ab" || po.airGapParams.VRFKeyHashHex != "cd" || po.airGapParams.Pledge != 1 || po.airGapParams.MarginDenom != 1 {
		t.Fatalf("registration airgap args = %+v, want cold/vrf ab/cd and params", po.airGapParams)
	}
}

func TestPoolRegistrationAcceptsStringAmounts(t *testing.T) {
	po := &fakePoolOps{cert: poolops.CertResult{PoolID: "pool1reg", CBORHex: "8a03"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","pledge":"9007199254740993","cost":"18446744073709551615","margin_num":1,"margin_denom":50}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/registration", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("registration string amounts = %d body %s", rec.Code, rec.Body.String())
	}
	if po.regParams.Pledge != 9007199254740993 || po.regParams.Cost != ^uint64(0) {
		t.Fatalf("registration string amount params = %+v, want pledge > safe int and max uint64 cost", po.regParams)
	}
}

func TestPoolRetirementCert(t *testing.T) {
	po := &fakePoolOps{cert: poolops.CertResult{PoolID: "pool1ret", CBORHex: "8304"}}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","epoch":500}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/cert", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pool1ret") {
		t.Fatalf("retirement cert = %d body %s", rec.Code, rec.Body.String())
	}
	if po.retirePassword != "pw" || po.retireColdVKey != "" || po.retireEpoch != 500 {
		t.Fatalf("retirement seed args = password %q cold %q epoch %d, want pw//500", po.retirePassword, po.retireColdVKey, po.retireEpoch)
	}

	rec = httptest.NewRecorder()
	body = bytes.NewBufferString(`{"cold_vkey_hex":"ab","epoch":501}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/cert", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("retirement airgap cert = %d, want 200", rec.Code)
	}
	if po.retirePassword != "" || po.retireColdVKey != "ab" || po.retireEpoch != 501 {
		t.Fatalf("retirement airgap args = password %q cold %q epoch %d, want /ab/501", po.retirePassword, po.retireColdVKey, po.retireEpoch)
	}
}

func TestPoolRetirementSubmitGatedWhileSyncing(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","epoch":500}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/submit", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("retirement submit while syncing = %d, want 503", rec.Code)
	}
}

func TestPoolRetirementSubmitReady(t *testing.T) {
	po := &fakePoolOps{tx: poolops.TxResult{TxHash: "feedface"}}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","epoch":500}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/submit", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "feedface") {
		t.Fatalf("retirement submit ready = %d body %s", rec.Code, rec.Body.String())
	}
	if po.submitPassword != "pw" || po.submitEpoch != 500 {
		t.Fatalf("submit args = password %q epoch %d, want pw/500", po.submitPassword, po.submitEpoch)
	}
}

func TestPoolRetirementSubmitRejected422(t *testing.T) {
	po := &fakePoolOps{submitErr: fmt.Errorf("%w: ledger rule X", poolops.ErrSubmitRejected)}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","epoch":500}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/submit", body))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("retirement submit rejected = %d, want 422", rec.Code)
	}
}

func TestVaultUnlockAttachesPoolWallet(t *testing.T) {
	// Unlocking the vault must also bind the active wallet to the pool-ops service
	// so credential/cert builders know which seed to derive from.
	st := readyStatuser()
	po := &fakePoolOps{}
	fv := &fakeVault{
		exists:  true,
		locked:  true,
		wallets: []vault.WalletMeta{{ID: "w1", Name: "main", Network: "preview", Account: sampleAccount("preview")}},
	}
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, po, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/unlock", bytes.NewBufferString(`{"password":"valid-vault-password"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault/unlock = %d, want 200", rec.Code)
	}
	if !po.setAccountCalled {
		t.Fatal("pool service was not attached to the active wallet on vault unlock")
	}
}

// --- TPM routes -------------------------------------------------------------

func TestTPMStatusReturnsProbeResult(t *testing.T) {
	fv := &fakeVault{tpmStatus: vault.TPMStatusInfo{
		Available: true,
		Reason:    "",
		Enabled:   false,
		PCRBound:  false,
	}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vault/tpm/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vault/tpm/status = %d, want 200", rec.Code)
	}
	var got tpmStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Available || got.Enabled || got.PCRBound {
		t.Fatalf("tpm status = %+v, want available=true enabled=false pcrBound=false", got)
	}
}

func TestTPMStatusReturnsUnavailableWithReason(t *testing.T) {
	fv := &fakeVault{tpmStatus: vault.TPMStatusInfo{
		Available: false,
		Reason:    "no TPM device found",
		Enabled:   false,
		PCRBound:  false,
	}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vault/tpm/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vault/tpm/status = %d, want 200", rec.Code)
	}
	var got tpmStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Available || got.Reason != "no TPM device found" {
		t.Fatalf("tpm status = %+v, want available=false reason='no TPM device found'", got)
	}
}

func TestTPMStatusReturnsEnabledAndPCRBound(t *testing.T) {
	fv := &fakeVault{tpmStatus: vault.TPMStatusInfo{
		Available: true,
		Enabled:   true,
		PCRBound:  true,
	}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vault/tpm/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vault/tpm/status = %d, want 200", rec.Code)
	}
	var got tpmStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Available || !got.Enabled || !got.PCRBound {
		t.Fatalf("tpm status = %+v, want available=true enabled=true pcrBound=true", got)
	}
}

func TestEnableTPMCallsVaultMethodWithPassword(t *testing.T) {
	fv := &fakeVault{tpmStatus: vault.TPMStatusInfo{Available: true}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"valid-vault-password","pcrBound":true}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/tpm/enable", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault/tpm/enable = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !fv.enableTPMCalled {
		t.Fatal("EnableTPM should have been called")
	}
	if fv.enableTPMPassword != "valid-vault-password" {
		t.Fatalf("EnableTPM password = %q, want valid-vault-password", fv.enableTPMPassword)
	}
	if !fv.enableTPMPCRBound {
		t.Fatal("EnableTPM pcrBound should be true")
	}
}

func TestEnableTPMWithoutPCRBound(t *testing.T) {
	fv := &fakeVault{tpmStatus: vault.TPMStatusInfo{Available: true}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"valid-vault-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/tpm/enable", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault/tpm/enable no pcrBound = %d, want 200", rec.Code)
	}
	if fv.enableTPMPCRBound {
		t.Fatal("EnableTPM pcrBound should default to false")
	}
}

func TestEnableTPMWrongPasswordReturns401(t *testing.T) {
	fv := &fakeVault{
		tpmStatus:    vault.TPMStatusInfo{Available: true},
		enableTPMErr: fmt.Errorf("%w: bad", vault.ErrWrongPassword),
	}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"wrong-but-long-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/tpm/enable", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /vault/tpm/enable wrong password = %d, want 401", rec.Code)
	}
}

func TestEnableTPMUnavailableReturns409(t *testing.T) {
	fv := &fakeVault{
		tpmStatus:    vault.TPMStatusInfo{Available: false, Reason: "no device"},
		enableTPMErr: fmt.Errorf("%w: no device", vault.ErrTPMUnavailable),
	}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"valid-vault-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/tpm/enable", body))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /vault/tpm/enable unavailable = %d, want 409", rec.Code)
	}
}

func TestEnableTPMRequiresPassword(t *testing.T) {
	// Both a missing and a too-short password must fail the shared
	// MinPasswordLen floor (via requirePassword) without touching the vault.
	for _, body := range []string{`{}`, `{"password":"short"}`} {
		fv := &fakeVault{tpmStatus: vault.TPMStatusInfo{Available: true}}
		h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/tpm/enable", bytes.NewBufferString(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST /vault/tpm/enable body %s = %d, want 400", body, rec.Code)
		}
		if fv.enableTPMCalled {
			t.Fatalf("EnableTPM should not be called for body %s", body)
		}
	}
}

func TestDisableTPMCallsVaultMethodWithPassword(t *testing.T) {
	fv := &fakeVault{}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"valid-vault-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/tpm/disable", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /vault/tpm/disable = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !fv.disableTPMCalled {
		t.Fatal("DisableTPM should have been called")
	}
	if fv.disableTPMPassword != "valid-vault-password" {
		t.Fatalf("DisableTPM password = %q, want valid-vault-password", fv.disableTPMPassword)
	}
}

func TestDisableTPMWrongPasswordReturns401(t *testing.T) {
	fv := &fakeVault{disableTPMErr: fmt.Errorf("%w: bad", vault.ErrWrongPassword)}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"wrong-but-long-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/tpm/disable", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /vault/tpm/disable wrong password = %d, want 401", rec.Code)
	}
}

func TestDisableTPMRequiresPassword(t *testing.T) {
	// Both a missing and a too-short password must fail the shared
	// MinPasswordLen floor (via requirePassword) without touching the vault.
	for _, body := range []string{`{}`, `{"password":"short"}`} {
		fv := &fakeVault{}
		h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vault/tpm/disable", bytes.NewBufferString(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST /vault/tpm/disable body %s = %d, want 400", body, rec.Code)
		}
		if fv.disableTPMCalled {
			t.Fatalf("DisableTPM should not be called for body %s", body)
		}
	}
}

func TestTPMRoutesRejectTrailingJSON(t *testing.T) {
	// The TPM routes must validate bodies as strictly as the other POST routes
	// (decodeBody): a body with trailing JSON tokens is malformed and must be
	// rejected without touching the vault.
	for _, route := range []string{"/vault/tpm/enable", "/vault/tpm/disable"} {
		fv := &fakeVault{tpmStatus: vault.TPMStatusInfo{Available: true}}
		h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
		rec := httptest.NewRecorder()
		body := bytes.NewBufferString(`{"password":"valid-vault-password"}{"junk":true}`)
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, route, body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST %s with trailing JSON = %d, want 400", route, rec.Code)
		}
		if fv.enableTPMCalled || fv.disableTPMCalled {
			t.Fatalf("POST %s with trailing JSON must not touch the vault", route)
		}
	}
}

// fakeNodeLookup implements NodeLookup for the pool/DRep/handle lookup
// endpoint tests.
type fakeNodeLookup struct {
	pool    chain.PoolInfo
	poolErr error
	drep    chain.DRepInfo
	drepErr error

	assetAddrs    []chain.AssetAddress
	assetErr      error
	gotAssetUnits []string
}

func (f *fakeNodeLookup) Pool(_ context.Context, _ string) (chain.PoolInfo, error) {
	return f.pool, f.poolErr
}

func (f *fakeNodeLookup) DRep(_ context.Context, _ string) (chain.DRepInfo, error) {
	return f.drep, f.drepErr
}

func (f *fakeNodeLookup) AssetAddresses(_ context.Context, asset string) ([]chain.AssetAddress, error) {
	f.gotAssetUnits = append(f.gotAssetUnits, asset)
	return f.assetAddrs, f.assetErr
}

func TestHandleLookupUnavailableWithoutLookup(t *testing.T) {
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "mainnet", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/handle/chris", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/handle/chris with no lookup = %d, want 503", rec.Code)
	}
}

func TestHandleLookupResolvesOnMainnet(t *testing.T) {
	lk := &fakeNodeLookup{assetAddrs: []chain.AssetAddress{{Address: "addr1abc", Quantity: "1"}}}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, lk, &fakePoolOps{}, nil, "mainnet", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/handle/$chris", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/handle/$chris = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got handleInfo
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Handle != "chris" || got.Address != "addr1abc" {
		t.Fatalf("unexpected handle info: %+v", got)
	}
	wantUnit := "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a" + "6368726973"
	if len(lk.gotAssetUnits) != 1 || lk.gotAssetUnits[0] != wantUnit {
		t.Fatalf("queried asset unit = %v, want [%s]", lk.gotAssetUnits, wantUnit)
	}
}

func TestHandleLookupResolvesOnPreview(t *testing.T) {
	lk := &fakeNodeLookup{assetAddrs: []chain.AssetAddress{{Address: "addr_test1abc", Quantity: "1"}}}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, lk, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/handle/$chris", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/handle/$chris on preview = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got handleInfo
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Handle != "chris" || got.Address != "addr_test1abc" {
		t.Fatalf("unexpected handle info: %+v", got)
	}
	wantUnit := "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a" + "6368726973"
	if len(lk.gotAssetUnits) != 1 || lk.gotAssetUnits[0] != wantUnit {
		t.Fatalf("queried asset unit = %v, want [%s]", lk.gotAssetUnits, wantUnit)
	}
}

func TestHandleLookupWithoutDollarSign(t *testing.T) {
	lk := &fakeNodeLookup{assetAddrs: []chain.AssetAddress{{Address: "addr1abc"}}}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, lk, &fakePoolOps{}, nil, "mainnet", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/handle/chris", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/handle/chris = %d, want 200", rec.Code)
	}
}

func TestHandleLookupNotFoundOnInvalidNetwork(t *testing.T) {
	lk := &fakeNodeLookup{assetAddrs: []chain.AssetAddress{{Address: "addr1abc"}}}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, lk, &fakePoolOps{}, nil, "mainnte", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/handle/$chris", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /wallet/handle/$chris on invalid network = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	if len(lk.gotAssetUnits) != 0 {
		t.Fatalf("invalid-network lookup should not query the node, got %v", lk.gotAssetUnits)
	}
}

func TestHandleLookupNotFoundWhenNodeHasNotSeenAsset(t *testing.T) {
	lk := &fakeNodeLookup{assetErr: chain.ErrNotFound}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, lk, &fakePoolOps{}, nil, "mainnet", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/handle/$chris", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /wallet/handle/$chris unseen asset = %d, want 404", rec.Code)
	}
}

func TestHandleLookupBadGatewayOnHardError(t *testing.T) {
	lk := &fakeNodeLookup{assetErr: errors.New("node exploded")}
	h := NewHandler(readyStatuser(), &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, lk, &fakePoolOps{}, nil, "mainnet", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/handle/$chris", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("GET /wallet/handle/$chris hard error = %d, want 502", rec.Code)
	}
}

func TestHandleLookupGatedWhileStarting(t *testing.T) {
	lk := &fakeNodeLookup{assetAddrs: []chain.AssetAddress{{Address: "addr1abc"}}}
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, lk, &fakePoolOps{}, nil, "mainnet", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/handle/$chris", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/handle/$chris while starting = %d, want 503", rec.Code)
	}
}

func TestDexRoutesAbsentWhenQuoterNil(t *testing.T) {
	// dx is nil unless the node is on mainnet (see NewHandler wiring); the DEX
	// routes must not be registered at all, so they fall through to the SPA/404
	// handler rather than e.g. panicking on a nil DexQuoter.
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, nil, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/dex/pools", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /wallet/dex/pools with nil quoter = %d, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	body := bytes.NewBufferString(`{"asset_in":"lovelace","asset_out":"dead","amount_in":"1000000"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/dex/quote", body))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /wallet/dex/quote with nil quoter = %d, want 404", rec.Code)
	}
}

func TestDexPoolsReturnsOK(t *testing.T) {
	dx := &fakeDexQuoter{pools: []dex.Pool{
		{Protocol: "minswap-v2", PoolID: "pool1", AssetX: "lovelace", AssetY: "deadbeef"},
	}}
	h := NewHandler(fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, dx, "mainnet", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/dex/pools", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/dex/pools = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Pools []dex.Pool `json:"pools"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.Pools) != 1 || got.Pools[0].PoolID != "pool1" {
		t.Fatalf("unexpected pools in response: %+v", got.Pools)
	}
}

func TestDexPoolsRequiresReadyNode(t *testing.T) {
	// The DEX routes are read-gated like other wallet reads: a node that
	// cannot yet serve queries must return 503, not reach the DexQuoter.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	dx := &fakeDexQuoter{}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, dx, "mainnet", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/dex/pools", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/dex/pools while starting = %d, want 503", rec.Code)
	}
}

func TestDexQuoteReturnsOK(t *testing.T) {
	dx := &fakeDexQuoter{quote: dex.Quote{
		Protocol: "minswap-v2", AssetIn: "lovelace", AssetOut: "deadbeef",
		AmountIn: "1000000", AmountOut: "500000", Route: "minswap-v2 lovelace→deadbeef",
	}}
	h := NewHandler(fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, dx, "mainnet", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"asset_in":"lovelace","asset_out":"deadbeef","amount_in":"1000000"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/dex/quote", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/dex/quote = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if dx.gotAssetIn != "lovelace" || dx.gotAssetOut != "deadbeef" || dx.gotAmountIn != 1000000 {
		t.Fatalf("Quote called with unexpected args: in=%q out=%q amount=%d",
			dx.gotAssetIn, dx.gotAssetOut, dx.gotAmountIn)
	}
	var got dex.Quote
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.AmountOut != "500000" {
		t.Fatalf("amount_out = %q, want 500000", got.AmountOut)
	}
}

func TestDexQuoteInvalidAmountReturns400(t *testing.T) {
	dx := &fakeDexQuoter{}
	h := NewHandler(fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, dx, "mainnet", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"asset_in":"lovelace","asset_out":"deadbeef","amount_in":"not-a-number"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/dex/quote", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet/dex/quote with bad amount_in = %d, want 400", rec.Code)
	}
	if dx.gotAssetIn != "" {
		t.Fatal("Quote must not be called when amount_in fails to parse")
	}
}

func TestDexQuoteRejectsTrailingJSON(t *testing.T) {
	dx := &fakeDexQuoter{}
	h := NewHandler(fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, dx, "mainnet", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"asset_in":"lovelace","asset_out":"deadbeef","amount_in":"1000000"}{"junk":true}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/dex/quote", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet/dex/quote with trailing JSON = %d, want 400", rec.Code)
	}
	if dx.gotAssetIn != "" {
		t.Fatal("Quote must not be called when the request body has trailing JSON")
	}
}

func TestDexQuoteErrorMapping(t *testing.T) {
	// serveDex maps the dex package's sentinel errors to distinct HTTP status
	// codes; anything else falls back to 500.
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"invalid request", fmt.Errorf("%w: bad unit", dex.ErrInvalidRequest), http.StatusBadRequest},
		{"no route", dex.ErrNoRoute, http.StatusNotFound},
		{"not mainnet", dex.ErrNotMainnet, http.StatusUnprocessableEntity},
		{"unknown error", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dx := &fakeDexQuoter{quoteErr: tc.err}
			h := NewHandler(fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeContacts{}, nil, &fakePoolOps{}, dx, "mainnet", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			body := bytes.NewBufferString(`{"asset_in":"lovelace","asset_out":"deadbeef","amount_in":"1000000"}`)
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/dex/quote", body))
			if rec.Code != tc.want {
				t.Fatalf("POST /wallet/dex/quote with %s = %d, want %d: %s", tc.name, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
