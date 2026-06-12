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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

type fakeStatuser struct{ s supervisor.Status }

func (f fakeStatuser) Status() supervisor.Status { return f.s }

func TestHealthAlwaysOK(t *testing.T) {
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, "preview")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health = %d, want 200", rec.Code)
	}
}

func TestStatusReturnsSnapshot(t *testing.T) {
	want := supervisor.Status{State: supervisor.StateSyncing, Tip: 42, CaughtUp: true}
	h := NewHandler(fakeStatuser{s: want}, &fakeWallet{}, &fakeSpender{}, "preview")
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

// fakeWallet is stateful like the real service: queries return
// wallet.ErrNoWallet until SetWallet has been called.
type fakeWallet struct {
	setErr           error
	balance          wallet.Balance
	set              bool
	setAccountCalled bool
	gotNetwork       string
}

func (f *fakeWallet) SetWallet(_, network string, _ int) (*wallet.Account, error) {
	if f.setErr != nil {
		return nil, f.setErr
	}
	f.set = true
	f.gotNetwork = network
	return &wallet.Account{StakeAddress: "stake_test1x", ReceiveAddresses: []string{"addr_test1a"}}, nil
}

func (f *fakeWallet) SetAccount(acct *wallet.Account) error {
	if acct == nil {
		return errors.New("nil account")
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

func TestWalletSetAndBalanceReady(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fw := &fakeWallet{balance: wallet.Balance{Lovelace: "1234"}}
	h := NewHandler(st, fw, &fakeSpender{}, "preview")

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/balance = %d, want 200", rec.Code)
	}
	var bal wallet.Balance
	if err := json.NewDecoder(rec.Body).Decode(&bal); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bal.Lovelace != "1234" {
		t.Fatalf("lovelace = %q, want 1234", bal.Lovelace)
	}
}

func TestWalletGatedWhileStarting(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, "preview")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/balance while starting = %d, want 503", rec.Code)
	}
}

func TestWalletNoWalletConflict(t *testing.T) {
	// No POST /wallet first: the natural no-wallet path must yield 409.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	for _, path := range []string{"/wallet/balance", "/wallet/addresses", "/wallet/transactions", "/wallet/delegation"} {
		t.Run(path, func(t *testing.T) {
			h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, "preview")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusConflict {
				t.Fatalf("GET %s with no wallet = %d, want 409", path, rec.Code)
			}
		})
	}
}

func TestWalletNetworkMismatch(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"mainnet"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet with mismatched network = %d, want 400", rec.Code)
	}
}

func TestWalletDefaultNetworkIsNodeNetwork(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fw := &fakeWallet{}
	h := NewHandler(st, fw, &fakeSpender{}, "preprod")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet without network = %d, want 200", rec.Code)
	}
	if fw.gotNetwork != "preprod" {
		t.Fatalf("SetWallet got network %q, want preprod (node network)", fw.gotNetwork)
	}
}

func TestWalletSetError(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	h := NewHandler(st, &fakeWallet{setErr: errors.New("invalid mnemonic")}, &fakeSpender{}, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"bad","network":"preview"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet with derive error = %d, want 400", rec.Code)
	}
}

// fakeSpender implements the api.Spender interface for handler tests.
type fakeSpender struct {
	setErr     error
	buildErr   error
	confirmErr error
	preview    spend.Preview
	result     spend.TxResult
	setCalled  bool
	gotNetwork string
	confirmID  string
}

func (f *fakeSpender) SetWallet(_, network, _ string) (*wallet.Account, error) {
	if f.setErr != nil {
		return nil, f.setErr
	}
	f.setCalled = true
	f.gotNetwork = network
	return &wallet.Account{Network: network, StakeAddress: "stake_test1x", ReceiveAddresses: []string{"addr_test1a"}}, nil
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

func TestKeystoreSetupDoesNotRequireReady(t *testing.T) {
	// Setting up the keystore derives + encrypts; it must not need a synced node.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	fw := &fakeWallet{}
	sp := &fakeSpender{}
	h := NewHandler(st, fw, sp, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview","password":"spendpw1"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/keystore", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/keystore = %d, want 200", rec.Code)
	}
	if !sp.setCalled || sp.gotNetwork != "preview" {
		t.Fatalf("SetWallet not called as expected: called=%v network=%q", sp.setCalled, sp.gotNetwork)
	}
	if !fw.setAccountCalled || fw.gotNetwork != "preview" {
		t.Fatalf("read wallet not attached as expected: called=%v network=%q", fw.setAccountCalled, fw.gotNetwork)
	}
}

func TestKeystoreSetupEnablesReadWallet(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	fw := &fakeWallet{balance: wallet.Balance{Lovelace: "1234"}}
	h := NewHandler(st, fw, &fakeSpender{}, "preview")

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview","password":"spendpw1"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/keystore", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/keystore = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/balance after keystore setup = %d, want 200", rec.Code)
	}
}

func TestKeystorePasswordRequired(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/keystore", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet/keystore without password = %d, want 400", rec.Code)
	}
}

func TestKeystorePasswordTooShort(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{}
	h := NewHandler(st, &fakeWallet{}, sp, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview","password":"short"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/keystore", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet/keystore with short password = %d, want 400", rec.Code)
	}
	if sp.setCalled {
		t.Fatal("SetWallet should not be called with a short password")
	}
}

func TestKeystorePasswordCountsCharacters(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{}
	h := NewHandler(st, &fakeWallet{}, sp, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview","password":"\u00e9\u00e9\u00e9\u00e9"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/keystore", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet/keystore with four multibyte characters = %d, want 400", rec.Code)
	}
	if sp.setCalled {
		t.Fatal("SetWallet should not be called with fewer than 8 password characters")
	}
}

func TestKeystoreNetworkMismatch(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"mainnet","password":"spendpw1"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/keystore", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet/keystore with mismatched network = %d, want 400", rec.Code)
	}
}

func TestSpendSendReadyReturnsPreview(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{preview: spend.Preview{PendingID: "pend123", Fee: 170000}}
	h := NewHandler(st, &fakeWallet{}, sp, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":1000000}`)
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
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":1000000}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /wallet/send while syncing = %d, want 503", rec.Code)
	}
}

func TestSpendSendNoWalletConflict(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{buildErr: spend.ErrNoWallet}
	h := NewHandler(st, &fakeWallet{}, sp, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":1000000}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/send", body))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /wallet/send with no wallet = %d, want 409", rec.Code)
	}
}

func TestSpendConfirmReadyReturnsTxHash(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{result: spend.TxResult{TxHash: "deadbeef"}}
	h := NewHandler(st, &fakeWallet{}, sp, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"spendpw1"}`)
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
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"spendpw1"}`)
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
					bytes.NewBufferString(`{"password":"spendpw1"}`))
			} else {
				sp.buildErr = tc.err
				req = httptest.NewRequest(http.MethodPost, "/wallet/send",
					bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":1000000}`))
			}
			h := NewHandler(st, &fakeWallet{}, sp, "preview")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("%s: code = %d, want %d", tc.name, rec.Code, tc.wantCode)
			}
		})
	}
}
