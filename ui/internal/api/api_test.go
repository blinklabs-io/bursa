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

	"github.com/blinklabs-io/bursa/ui/internal/poolops"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

type fakeStatuser struct{ s supervisor.Status }

func (f fakeStatuser) Status() supervisor.Status { return f.s }

func TestHealthAlwaysOK(t *testing.T) {
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health = %d, want 200", rec.Code)
	}
}

func TestStatusReturnsSnapshot(t *testing.T) {
	want := supervisor.Status{State: supervisor.StateSyncing, Tip: 42, CaughtUp: true}
	h := NewHandler(fakeStatuser{s: want}, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, fw, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())

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
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/balance while starting = %d, want 503", rec.Code)
	}
}

func TestWalletGatedWhileBootstrapping(t *testing.T) {
	// Mithril bootstrap is not a servable state: reads must be gated (503).
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateBootstrapping}}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/balance while bootstrapping = %d, want 503", rec.Code)
	}
}

func TestWalletNoWalletConflict(t *testing.T) {
	// No POST /wallet first: the natural no-wallet path must yield 409.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	for _, path := range []string{"/wallet/balance", "/wallet/addresses", "/wallet/transactions", "/wallet/delegation"} {
		t.Run(path, func(t *testing.T) {
			h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, fw, &fakeSpender{}, &fakePoolOps{}, "preprod", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{setErr: errors.New("invalid mnemonic")}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	signSig    string
	signKey    string
	signErr    error
	signAddr   string
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

func (f *fakeSpender) SignData(addr string, _ []byte, _ string) (string, string, error) {
	f.signAddr = addr
	if f.signErr != nil {
		return "", "", f.signErr
	}
	return f.signSig, f.signKey, nil
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

	creds    poolops.Credentials
	kes      poolops.KESPeriodInfo
	opcert   poolops.OpCert
	payload  poolops.OpCertPayload
	metadata poolops.MetadataResult
	cert     poolops.CertResult
	tx       poolops.TxResult
	poolID   string
}

func (f *fakePoolOps) SetAccount(_ *wallet.Account) { f.setAccountCalled = true }

func (f *fakePoolOps) Credentials(_ string) (poolops.Credentials, error) {
	return f.creds, f.credErr
}

func (f *fakePoolOps) KESPeriod(_ context.Context) (poolops.KESPeriodInfo, error) {
	return f.kes, f.kesErr
}

func (f *fakePoolOps) IssueOpCert(_ string, _ uint32, _, _ uint64) (poolops.OpCert, error) {
	return f.opcert, f.opcertErr
}

func (f *fakePoolOps) RotateKES(_ string, _ uint32, _, _ uint64) (poolops.OpCert, error) {
	return f.opcert, f.opcertErr
}

func (f *fakePoolOps) OpCertPayload(_ string, _, _ uint64) (poolops.OpCertPayload, error) {
	return f.payload, f.opcertErr
}

func (f *fakePoolOps) AssembleOpCert(_, _, _ string, _, _ uint64) (poolops.OpCert, error) {
	return f.opcert, f.opcertErr
}

func (f *fakePoolOps) BuildMetadata(_ poolops.MetadataInput) (poolops.MetadataResult, error) {
	return f.metadata, f.metadataErr
}

func (f *fakePoolOps) PoolIDFromColdVKey(_ string) (string, string, error) {
	return f.poolID, f.poolID, f.idErr
}

func (f *fakePoolOps) BuildRegistrationFromSeed(_ string, _ poolops.RegistrationParams) (poolops.CertResult, error) {
	return f.cert, f.regErr
}

func (f *fakePoolOps) BuildRegistrationAirGap(_ poolops.AirGapRegistrationParams) (poolops.CertResult, error) {
	return f.cert, f.regErr
}

func (f *fakePoolOps) BuildRetirementCert(_, _ string, _ uint64) (poolops.CertResult, error) {
	return f.cert, f.retireErr
}

func (f *fakePoolOps) SubmitRetirement(_ context.Context, _ string, _ uint64) (poolops.TxResult, error) {
	return f.tx, f.submitErr
}

func TestSignDataReturnsSignature(t *testing.T) {
	// Ungated: message signing needs no synced node, only the keystore.
	sp := &fakeSpender{signSig: "84a1deadbeef", signKey: "a4010103"}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"address":"a","message":"m","password":"bad"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-data", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-data with wrong password = %d, want 401", rec.Code)
	}
}

func TestKeystoreSetupDoesNotRequireReady(t *testing.T) {
	// Setting up the keystore derives + encrypts; it must not need a synced node.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	fw := &fakeWallet{}
	sp := &fakeSpender{}
	h := NewHandler(st, fw, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview","password":"valid-spend-password"}`)
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
	h := NewHandler(st, fw, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview","password":"valid-spend-password"}`)
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
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{}, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{}, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"mainnet","password":"valid-spend-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/keystore", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /wallet/keystore with mismatched network = %d, want 400", rec.Code)
	}
}

func TestSpendSendReadyReturnsPreview(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	sp := &fakeSpender{preview: spend.Preview{PendingID: "pend123", Fee: "170000"}}
	h := NewHandler(st, &fakeWallet{}, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{}, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{}, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
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
			h := NewHandler(st, &fakeWallet{}, sp, &fakePoolOps{}, "preview", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("%s: code = %d, want %d", tc.name, rec.Code, tc.wantCode)
			}
		})
	}
}

// --- Pool operations (SPO) ---

// readyStatuser returns a fully-synced node for pool ops that need a node.
func readyStatuser() fakeStatuser {
	return fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
}

func TestPoolCredentialsReturnsCreds(t *testing.T) {
	po := &fakePoolOps{creds: poolops.Credentials{PoolID: "pool1abc", Network: "preview"}}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"spend-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/credentials", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/pool/credentials = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pool1abc") {
		t.Fatalf("response missing pool ID: %s", rec.Body.String())
	}
}

func TestPoolCredentialsNoWalletConflict(t *testing.T) {
	po := &fakePoolOps{credErr: poolops.ErrNoWallet}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"x"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/credentials", body))
	if rec.Code != http.StatusConflict {
		t.Fatalf("credentials with no wallet = %d, want 409", rec.Code)
	}
}

func TestPoolCredentialsWrongPassword401(t *testing.T) {
	po := &fakePoolOps{credErr: fmt.Errorf("%w: bad", poolops.ErrWrongPassword)}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"bad"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/credentials", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("credentials wrong password = %d, want 401", rec.Code)
	}
}

func TestPoolKESPeriodGatedWhileStarting(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/pool/kes-period", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("kes-period while starting = %d, want 503", rec.Code)
	}
}

func TestPoolKESPeriodReady(t *testing.T) {
	po := &fakePoolOps{kes: poolops.KESPeriodInfo{CurrentPeriod: 7, SlotsPerKESPeriod: 129600}}
	h := NewHandler(readyStatuser(), &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
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
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","kes_index":0,"issue_number":3,"kes_period":7}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("opcert issue = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "abcd") {
		t.Fatalf("opcert response missing kes vkey: %s", rec.Body.String())
	}
}

func TestPoolOpCertRotate(t *testing.T) {
	po := &fakePoolOps{opcert: poolops.OpCert{IssueNumber: 4, KESIndex: 1}}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","new_kes_index":1,"prev_issue_number":3,"kes_period":7}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert/rotate", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("opcert rotate = %d, want 200", rec.Code)
	}
}

func TestPoolOpCertPayloadAndAssembleAirGap(t *testing.T) {
	po := &fakePoolOps{
		payload: poolops.OpCertPayload{PayloadHex: "8203", KesVKeyHex: "ab"},
		opcert:  poolops.OpCert{IssueNumber: 1},
	}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"kes_vkey_hex":"ab","issue_number":1,"kes_period":2}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert/payload", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "8203") {
		t.Fatalf("opcert payload = %d body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	body = bytes.NewBufferString(`{"cold_vkey_hex":"aa","kes_vkey_hex":"bb","signature_hex":"cc","issue_number":1,"kes_period":2}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert/assemble", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("opcert assemble = %d, want 200", rec.Code)
	}
}

func TestPoolAssembleOpCertBadSignature400(t *testing.T) {
	po := &fakePoolOps{opcertErr: fmt.Errorf("%w: bad sig", poolops.ErrInvalidRequest)}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"cold_vkey_hex":"aa","kes_vkey_hex":"bb","signature_hex":"00","issue_number":1,"kes_period":2}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/opcert/assemble", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("assemble bad sig = %d, want 400", rec.Code)
	}
}

func TestPoolMetadataBuilder(t *testing.T) {
	po := &fakePoolOps{metadata: poolops.MetadataResult{JSON: `{"name":"P"}`, HashHex: "deadbeef"}}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"name":"P","ticker":"P","homepage":"https://x","description":"d"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/metadata", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "deadbeef") {
		t.Fatalf("metadata = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestPoolIDFromColdVKey(t *testing.T) {
	po := &fakePoolOps{poolID: "pool1xyz"}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"cold_vkey_hex":"` + strings.Repeat("ab", 32) + `"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/id", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pool1xyz") {
		t.Fatalf("pool id = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestPoolRegistrationSeedAndAirGap(t *testing.T) {
	po := &fakePoolOps{cert: poolops.CertResult{PoolID: "pool1reg", CBORHex: "8a03"}}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","pledge":1,"cost":1,"margin_num":1,"margin_denom":50}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/registration", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pool1reg") {
		t.Fatalf("registration seed = %d body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	body = bytes.NewBufferString(`{"cold_vkey_hex":"ab","vrf_key_hash_hex":"cd","pledge":1,"cost":1,"margin_num":0,"margin_denom":1}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/registration/airgap", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("registration airgap = %d, want 200", rec.Code)
	}
}

func TestPoolRetirementCert(t *testing.T) {
	po := &fakePoolOps{cert: poolops.CertResult{PoolID: "pool1ret", CBORHex: "8304"}}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","epoch":500}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/cert", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pool1ret") {
		t.Fatalf("retirement cert = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestPoolRetirementSubmitGatedWhileSyncing(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakePoolOps{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","epoch":500}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/submit", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("retirement submit while syncing = %d, want 503", rec.Code)
	}
}

func TestPoolRetirementSubmitReady(t *testing.T) {
	po := &fakePoolOps{tx: poolops.TxResult{TxHash: "feedface"}}
	h := NewHandler(readyStatuser(), &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","epoch":500}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/submit", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "feedface") {
		t.Fatalf("retirement submit ready = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestPoolRetirementSubmitRejected422(t *testing.T) {
	po := &fakePoolOps{submitErr: fmt.Errorf("%w: ledger rule X", poolops.ErrSubmitRejected)}
	h := NewHandler(readyStatuser(), &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw","epoch":500}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/pool/retirement/submit", body))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("retirement submit rejected = %d, want 422", rec.Code)
	}
}

func TestKeystoreSetupAttachesPoolWallet(t *testing.T) {
	st := readyStatuser()
	po := &fakePoolOps{}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, po, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"mnemonic":"x x x","network":"preview","password":"valid-spend-password"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/keystore", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/keystore = %d, want 200", rec.Code)
	}
	if !po.setAccountCalled {
		t.Fatal("pool service was not attached to the active wallet on keystore setup")
	}
}
