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

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
	"github.com/blinklabs-io/bursa/ui/internal/nft"
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

func TestHealthAlwaysOK(t *testing.T) {
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health = %d, want 200", rec.Code)
	}
}

func TestStatusReturnsSnapshot(t *testing.T) {
	want := supervisor.Status{State: supervisor.StateSyncing, Tip: 42, CaughtUp: true}
	h := NewHandler(fakeStatuser{s: want}, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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

func (f *fakeWallet) Delegation(_ context.Context) (wallet.DelegationView, error) {
	if !f.set {
		return wallet.DelegationView{}, wallet.ErrNoWallet
	}
	return wallet.DelegationView{}, nil
}

// --- Vault lifecycle --------------------------------------------------------

func TestVaultStatusReports(t *testing.T) {
	fv := &fakeVault{exists: true, locked: true, wallets: []vault.WalletMeta{{ID: "a"}, {ID: "b"}}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler(), WithLegacyKeystore(legacy))
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
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, fv, fw, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())

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
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, fv, fw, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, fv, fw, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler(), WithLegacyKeystore(legacy))

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
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler(), WithLegacyKeystore(legacy))

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
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler(), WithLegacyKeystore(legacy))

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
	h := NewHandler(st, fv, fw, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())

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
	h := NewHandler(st, fv, &fakeWallet{}, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preprod", http.NotFoundHandler())
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
	h := NewHandler(st, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := `{"name":"main","mnemonic":"x x x","network":"preview","vault_password":"valid-vault-password","spend_password":"valid-spend-password"}`
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", bytes.NewBufferString(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /wallet duplicate = %d, want 409", rec.Code)
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
	h := NewHandler(st, fv, fw, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/nope/activate", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("activate unknown = %d, want 404", rec.Code)
	}
}

func TestDeleteWalletRequiresVaultPassword(t *testing.T) {
	fv := &fakeVault{exists: true, locked: false, wallets: []vault.WalletMeta{{ID: "w1"}}}
	h := NewHandler(fakeStatuser{}, fv, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, fv, fw, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/balance while starting = %d, want 503", rec.Code)
	}
}

func TestWalletGatedWhileBootstrapping(t *testing.T) {
	// Mithril bootstrap is not a servable state: reads must be gated (503).
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateBootstrapping}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/balance while bootstrapping = %d, want 503", rec.Code)
	}
}

func TestWalletNoActiveWalletConflict(t *testing.T) {
	// No active wallet bound: reads must yield 409 (the read service has no account).
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	for _, path := range []string{"/wallet/balance", "/wallet/addresses", "/wallet/transactions", "/wallet/delegation"} {
		t.Run(path, func(t *testing.T) {
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusConflict {
				t.Fatalf("GET %s with no active wallet = %d, want 409", path, rec.Code)
			}
		})
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

func TestSignDataReturnsSignature(t *testing.T) {
	// Ungated: message signing needs no synced node, only the keystore.
	sp := &fakeSpender{signSig: "84a1deadbeef", signKey: "a4010103"}
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"address":"a","message":"m","password":"bad"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-data", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-data with wrong password = %d, want 401", rec.Code)
	}
}

func TestSpendSendReadyReturnsPreview(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{preview: spend.Preview{PendingID: "pend123", Fee: "170000"}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, sp, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
			h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeNFTs{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, set, &fakeNFTs{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"enabled":true}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/history-expiry", body))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT history-expiry with persist error = %d, want 500", rec.Code)
	}
}

// fakeNFTs implements the api.NFTs interface for handler tests. It records the
// enable toggle and serves a fixed image (or 403 when disabled), without ever
// touching IPFS.
type fakeNFTs struct {
	enabled    bool
	list       []nft.NFT
	listErr    error
	imageBytes []byte
	servedUnit string
	setErr     error
}

func (f *fakeNFTs) List(_ context.Context) ([]nft.NFT, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.list, nil
}

func (f *fakeNFTs) ServeImage(_ context.Context, w http.ResponseWriter, unit string) {
	f.servedUnit = unit
	if !f.enabled {
		http.Error(w, "nft media disabled", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(f.imageBytes)
}

func (f *fakeNFTs) Enabled() bool { return f.enabled }

func (f *fakeNFTs) SetEnabled(enabled bool) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.enabled = enabled
	return nil
}

func TestNFTListReady(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	nf := &fakeNFTs{list: []nft.NFT{{Unit: "policyAtoken", Name: "Token A", ImageCID: "bafyimage", Cached: true}}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, nf, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/nft", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/nft = %d, want 200", rec.Code)
	}
	var got []nft.NFT
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Token A" || got[0].ImageCID != "bafyimage" || !got[0].Cached {
		t.Fatalf("unexpected nft list: %+v", got)
	}
}

func TestNFTListGatedWhileStarting(t *testing.T) {
	// Discovery is node-local but still needs a servable node (like other reads).
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, &fakeNFTs{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/nft", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/nft while starting = %d, want 503", rec.Code)
	}
}

func TestNFTListNoWalletConflict(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	nf := &fakeNFTs{listErr: nft.ErrNoWallet}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, nf, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/nft", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("GET /wallet/nft with no wallet = %d, want 409", rec.Code)
	}
}

func TestNFTImageDisabledReturns403(t *testing.T) {
	// Media off (the default): the image route must refuse, touching nothing.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	nf := &fakeNFTs{enabled: false}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, nf, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/nft/policyAtoken/image", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET image while media disabled = %d, want 403", rec.Code)
	}
}

func TestNFTImageEnabledServesBytes(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	nf := &fakeNFTs{enabled: true, imageBytes: []byte("\x89PNGfake")}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, nf, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/nft/policyAtoken/image", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET image while enabled = %d, want 200", rec.Code)
	}
	if nf.servedUnit != "policyAtoken" {
		t.Fatalf("served unit = %q, want policyAtoken", nf.servedUnit)
	}
	if rec.Body.String() != "\x89PNGfake" {
		t.Fatalf("image bytes not served: %q", rec.Body.String())
	}
}

func TestNFTSettingsToggle(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	nf := &fakeNFTs{}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, nf, "preview", http.NotFoundHandler())

	// Default: disabled.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/settings/nft-media", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("GET nft-media setting = %d body=%q, want 200 enabled:false", rec.Code, rec.Body.String())
	}

	// Enable it.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/nft-media",
		bytes.NewBufferString(`{"enabled":true}`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("PUT nft-media enable = %d body=%q, want 200 enabled:true", rec.Code, rec.Body.String())
	}
	if !nf.enabled {
		t.Fatal("SetEnabled(true) not applied")
	}

	// And back off.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/wallet/settings/nft-media",
		bytes.NewBufferString(`{"enabled":false}`)))
	if rec.Code != http.StatusOK || nf.enabled {
		t.Fatalf("PUT nft-media disable = %d enabled=%v, want 200 disabled", rec.Code, nf.enabled)
	}
}

// TestNFTNilServiceDegradesGracefully checks the routes don't panic when the
// nft service is nil (media not wired in this build).
func TestNFTNilServiceDegradesGracefully(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	h := NewHandler(st, &fakeVault{}, &fakeWallet{}, &fakeSpender{}, &fakeSettings{}, nil, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/nft", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/nft with nil nft service = %d, want 503", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/settings/nft-media", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("GET nft-media with nil service = %d body=%q, want 200 enabled:false", rec.Code, rec.Body.String())
	}
}
