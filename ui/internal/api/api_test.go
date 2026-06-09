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

	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

type fakeStatuser struct{ s supervisor.Status }

func (f fakeStatuser) Status() supervisor.Status { return f.s }

func TestHealthAlwaysOK(t *testing.T) {
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, "preview")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health = %d, want 200", rec.Code)
	}
}

func TestStatusReturnsSnapshot(t *testing.T) {
	want := supervisor.Status{State: supervisor.StateSyncing, Tip: 42, CaughtUp: true}
	h := NewHandler(fakeStatuser{s: want}, &fakeWallet{}, "preview")
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
	setErr     error
	balance    wallet.Balance
	set        bool
	gotNetwork string
}

func (f *fakeWallet) SetWallet(_, network string, _ int) (*wallet.Account, error) {
	if f.setErr != nil {
		return nil, f.setErr
	}
	f.set = true
	f.gotNetwork = network
	return &wallet.Account{StakeAddress: "stake_test1x", ReceiveAddresses: []string{"addr_test1a"}}, nil
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
	h := NewHandler(st, fw, "preview")

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
	h := NewHandler(st, &fakeWallet{}, "preview")
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
			h := NewHandler(st, &fakeWallet{}, "preview")
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
	h := NewHandler(st, &fakeWallet{}, "preview")
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
	h := NewHandler(st, fw, "preprod")
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
	h := NewHandler(st, &fakeWallet{setErr: errors.New("invalid mnemonic")}, "preview")
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"bad","network":"preview"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet with derive error = %d, want 400", rec.Code)
	}
}
