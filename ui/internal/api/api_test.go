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

	"github.com/blinklabs-io/bursa/ui/internal/multisig"
	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// newTestHandler wraps NewHandler, injecting a default no-op MultiSig so the
// existing tests (which predate multi-sig) keep their original argument shape.
// Tests that exercise multi-sig routes call NewHandler directly with their own.
func newTestHandler(st Statuser, wl Wallet, sp Spender, network string, spa http.Handler) http.Handler {
	return NewHandler(st, wl, sp, &fakeMultiSig{}, network, spa)
}

// fakeMultiSig is a default-zero stub of the MultiSig surface for tests that do
// not exercise multi-sig endpoints.
type fakeMultiSig struct {
	accounts   []multisig.Account
	getAcct    multisig.Account
	getErr     error
	createAcct multisig.Account
	createErr  error
	myKey      multisig.MyKey
	myKeyErr   error
	balance    string
	balanceErr error
	built      multisig.UnsignedTx
	buildErr   error
	witness    multisig.Witness
	signErr    error
	tx         multisig.TxResult
	submitErr  error
}

func (f *fakeMultiSig) List() ([]multisig.Account, error)    { return f.accounts, nil }
func (f *fakeMultiSig) Get(string) (multisig.Account, error) { return f.getAcct, f.getErr }
func (f *fakeMultiSig) Create(multisig.CreateRequest) (multisig.Account, error) {
	return f.createAcct, f.createErr
}
func (f *fakeMultiSig) Delete(string) error                  { return nil }
func (f *fakeMultiSig) MyKey(string) (multisig.MyKey, error) { return f.myKey, f.myKeyErr }
func (f *fakeMultiSig) Balance(context.Context, string) (string, error) {
	return f.balance, f.balanceErr
}
func (f *fakeMultiSig) Build(context.Context, string, multisig.BuildRequest) (multisig.UnsignedTx, error) {
	return f.built, f.buildErr
}
func (f *fakeMultiSig) Sign(string, string) (multisig.Witness, error) { return f.witness, f.signErr }
func (f *fakeMultiSig) Submit(context.Context, string, string, []string) (multisig.TxResult, error) {
	return f.tx, f.submitErr
}

type fakeStatuser struct{ s supervisor.Status }

func (f fakeStatuser) Status() supervisor.Status { return f.s }

func TestHealthAlwaysOK(t *testing.T) {
	h := newTestHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health = %d, want 200", rec.Code)
	}
}

func TestStatusReturnsSnapshot(t *testing.T) {
	want := supervisor.Status{State: supervisor.StateSyncing, Tip: 42, CaughtUp: true}
	h := newTestHandler(fakeStatuser{s: want}, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, fw, &fakeSpender{}, "preview", http.NotFoundHandler())

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
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/balance", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /wallet/balance while starting = %d, want 503", rec.Code)
	}
}

func TestWalletGatedWhileBootstrapping(t *testing.T) {
	// Mithril bootstrap is not a servable state: reads must be gated (503).
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateBootstrapping}}
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
			h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, fw, &fakeSpender{}, "preprod", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{setErr: errors.New("invalid mnemonic")}, &fakeSpender{}, "preview", http.NotFoundHandler())
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

	// verify-data
	verifyValid   bool
	verifyAddr    string
	verifyErr     error
	gotVerifySig  string
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
	submitResult  spend.TxResult
	submitErr     error
	gotSubmitTx   string
	gotSubmitWit  string
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

func (f *fakeSpender) VerifyData(sig, _ string, msg []byte, hashed bool, expected string) (bool, string, error) {
	f.gotVerifySig = sig
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

func (f *fakeSpender) SignTx(unsignedTxCBOR, _ string) (spend.Witness, error) {
	f.gotSignTxCBOR = unsignedTxCBOR
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

func TestSignDataReturnsSignature(t *testing.T) {
	// Ungated: message signing needs no synced node, only the keystore.
	sp := &fakeSpender{signSig: "84a1deadbeef", signKey: "a4010103"}
	h := newTestHandler(fakeStatuser{}, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(fakeStatuser{}, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(fakeStatuser{}, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"signature":"84a1","key":"a401","message":"hi","expected_address":"addr_test1signed"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/verify-data", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/verify-data = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"valid":true`) ||
		!strings.Contains(rec.Body.String(), "addr_test1signed") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if sp.gotVerifySig != "84a1" || sp.gotVerifyMsg != "hi" || sp.gotVerifyExp != "addr_test1signed" {
		t.Fatalf("args not passed through: %+v", sp)
	}
}

func TestVerifyDataInvalidArgsReturns400(t *testing.T) {
	sp := &fakeSpender{verifyErr: fmt.Errorf("%w: bad hex", spend.ErrInvalidRequest)}
	h := newTestHandler(fakeStatuser{}, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"signature":"zz","key":"a4","message":"hi"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/verify-data", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("verify-data with bad input = %d, want 400", rec.Code)
	}
}

func TestExportUnsignedRequiresReady(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	// Offline signing must not need a synced node — only the keystore.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	sp := &fakeSpender{witness: spend.Witness{WitnessCBOR: "81825820"}}
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","password":"pw"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-tx", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /wallet/sign-tx = %d, want 200", rec.Code)
	}
	if sp.gotSignTxCBOR != "84a400" {
		t.Fatalf("unsigned tx not passed through: %q", sp.gotSignTxCBOR)
	}
	if !strings.Contains(rec.Body.String(), "81825820") {
		t.Fatalf("witness missing from body: %s", rec.Body.String())
	}
}

func TestSignTxWrongPasswordReturns401(t *testing.T) {
	sp := &fakeSpender{signTxErr: fmt.Errorf("%w: bad", spend.ErrWrongPassword)}
	h := newTestHandler(fakeStatuser{}, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","password":"bad"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/sign-tx", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sign-tx wrong password = %d, want 401", rec.Code)
	}
}

func TestSubmitSignedRequiresReady(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","witness_cbor":"zz"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/submit-signed", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("submit-signed bad witness = %d, want 400", rec.Code)
	}
}

func TestKeystoreSetupDoesNotRequireReady(t *testing.T) {
	// Setting up the keystore derives + encrypts; it must not need a synced node.
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateStarting}}
	fw := &fakeWallet{}
	sp := &fakeSpender{}
	h := newTestHandler(st, fw, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, fw, &fakeSpender{}, "preview", http.NotFoundHandler())

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
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
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
	h := newTestHandler(st, &fakeWallet{}, &fakeSpender{}, "preview", http.NotFoundHandler())
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
			h := newTestHandler(st, &fakeWallet{}, sp, "preview", http.NotFoundHandler())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("%s: code = %d, want %d", tc.name, rec.Code, tc.wantCode)
			}
		})
	}
}

// --- Multi-sig routes -------------------------------------------------------

func TestMultiSigListAndCreate(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	ms := &fakeMultiSig{
		accounts:   []multisig.Account{{ID: "abc", Label: "treasury", ScriptAddress: "addr_test1wscript"}},
		createAcct: multisig.Account{ID: "new1", Label: "joint", ScriptAddress: "addr_test1wnew"},
	}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, ms, "preview", http.NotFoundHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/multisig", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "treasury") {
		t.Fatalf("GET /wallet/multisig = %d body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	body := bytes.NewBufferString(`{"label":"joint","policy":{"threshold":2,"participants":[{"key_hash_hex":"aa"},{"key_hash_hex":"bb"}]}}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/multisig", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "addr_test1wnew") {
		t.Fatalf("POST /wallet/multisig = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestMultiSigGetUnknownReturns404(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	ms := &fakeMultiSig{getErr: fmt.Errorf("%w: x", multisig.ErrUnknownAccount)}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, ms, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/multisig/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET unknown account = %d, want 404", rec.Code)
	}
}

func TestMultiSigMyKey(t *testing.T) {
	// Ungated: derives from the keystore, no node needed.
	ms := &fakeMultiSig{myKey: multisig.MyKey{VKeyHex: "abcd", KeyHashHex: "deadbeef"}}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, ms, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"password":"pw"}`)
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/multisig/my-key", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "deadbeef") {
		t.Fatalf("POST /wallet/multisig/my-key = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestMultiSigMyKeyNoKeystoreReturns409(t *testing.T) {
	ms := &fakeMultiSig{myKeyErr: multisig.ErrNoKeystore}
	h := NewHandler(fakeStatuser{}, &fakeWallet{}, &fakeSpender{}, ms, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/multisig/my-key",
		bytes.NewBufferString(`{"password":"pw"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("my-key without keystore = %d, want 409", rec.Code)
	}
}

func TestMultiSigBuildGatedWhileSyncing(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateSyncing}}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, &fakeMultiSig{}, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/multisig/abc/build",
		bytes.NewBufferString(`{"to":"addr_test1recv","lovelace":"1000000"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("build while syncing = %d, want 503", rec.Code)
	}
}

func TestMultiSigSignAndSubmit(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	ms := &fakeMultiSig{
		witness: multisig.Witness{WitnessCBOR: "81a0"},
		tx:      multisig.TxResult{TxHash: "feedface"},
	}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, ms, "preview", http.NotFoundHandler())

	// Sign is ungated.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/multisig/sign",
		bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","password":"pw"}`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "81a0") {
		t.Fatalf("POST /wallet/multisig/sign = %d body %s", rec.Code, rec.Body.String())
	}

	// Submit needs a ready node.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/multisig/abc/submit",
		bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","witnesses":["81a0","81a1"]}`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "feedface") {
		t.Fatalf("POST /wallet/multisig/abc/submit = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestMultiSigSubmitBelowThresholdReturns400(t *testing.T) {
	st := fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}}
	ms := &fakeMultiSig{submitErr: fmt.Errorf("%w: have 1 of 2", multisig.ErrInvalidWitness)}
	h := NewHandler(st, &fakeWallet{}, &fakeSpender{}, ms, "preview", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/wallet/multisig/abc/submit",
		bytes.NewBufferString(`{"unsigned_tx_cbor":"84a400","witnesses":["81a0"]}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("submit below threshold = %d, want 400", rec.Code)
	}
}
