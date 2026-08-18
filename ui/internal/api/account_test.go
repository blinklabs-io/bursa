package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/vault"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// multiAccountVault returns a fakeVault holding one wallet with two derived
// accounts (indices 0 and 1), account 0 selected, wallet active.
func multiAccountVault() *fakeVault {
	a0 := sampleAccount("preview")
	a1 := sampleAccount("preview")
	a1.AccountIndex = 1
	a1.StakeAddress = "stake_test1acct1"
	a1.ReceiveAddresses = []string{"addr_test1acct1"}
	w := vault.WalletMeta{
		ID:       "w1",
		Name:     "main",
		Network:  "preview",
		Account:  a0,
		Accounts: []*wallet.Account{a0, a1},
		Type:     vault.WalletTypeFull,
	}
	return &fakeVault{exists: true, locked: false, wallets: []vault.WalletMeta{w}, activeID: "w1"}
}

func multiAcctHandler(v *fakeVault, fw *fakeWallet) http.Handler {
	return NewHandler(readyStatuser(), v, fw, &fakeSpender{}, &fakeSettings{},
		&fakeContacts{}, nil, &fakePoolOps{}, nil, &fakeMultiSig{}, "preview", http.NotFoundHandler())
}

func TestListAccounts(t *testing.T) {
	v := multiAccountVault()
	// Give each account a distinct balance so the assertions below actually
	// verify per-account attribution rather than a fixed balance echoed for
	// every row (a bug that binds account 0's balance to every account would
	// otherwise still pass a same-balance-for-all-accounts test).
	fw := &fakeWallet{set: true, balances: map[uint32]wallet.Balance{
		0: {Lovelace: "1000000"},
		1: {Lovelace: "2000000"},
	}}
	h := multiAcctHandler(v, fw)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/wallet/accounts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /wallet/accounts = %d body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		Accounts           []accountSummary `json:"accounts"`
		ActiveAccountIndex uint32           `json:"active_account_index"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode accounts response: %v (body=%s)", err, rec.Body.String())
	}
	if resp.ActiveAccountIndex != 0 {
		t.Fatalf("active_account_index = %d, want 0", resp.ActiveAccountIndex)
	}
	if len(resp.Accounts) != 2 {
		t.Fatalf("accounts len = %d, want 2 (body=%s)", len(resp.Accounts), rec.Body.String())
	}
	a0, a1 := resp.Accounts[0], resp.Accounts[1]
	if a0.Index != 0 || a0.Balance == nil || a0.Balance.Lovelace != "1000000" {
		t.Fatalf("account 0 = %+v, want index 0 balance 1000000", a0)
	}
	if a1.Index != 1 || a1.Label != "Account #1" || a1.FirstAddress != "addr_test1acct1" {
		t.Fatalf("account 1 = %+v, want index 1 / Account #1 / addr_test1acct1", a1)
	}
	if a1.Balance == nil || a1.Balance.Lovelace != "2000000" {
		t.Fatalf("account 1 balance = %+v, want 2000000 (distinct from account 0)", a1.Balance)
	}
}

func TestListAccountsNoActiveWallet(t *testing.T) {
	v := &fakeVault{exists: true, locked: false} // no active wallet
	h := multiAcctHandler(v, &fakeWallet{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/wallet/accounts", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("GET /wallet/accounts no active = %d, want 409", rec.Code)
	}
}

func TestSelectAccountRebinds(t *testing.T) {
	v := multiAccountVault()
	fw := &fakeWallet{set: true}
	h := multiAcctHandler(v, fw)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodPost, "/wallet/account/select", strings.NewReader(`{"account_index":1}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("select = %d body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"active_account_index":1`) {
		t.Fatalf("select response missing active_account_index 1: %s", body)
	}
	// The active-account view must reflect account 1 (multi-account switch).
	if !strings.Contains(body, `"stake_address":"stake_test1acct1"`) {
		t.Fatalf("select response stake address not account 1: %s", body)
	}
	// bindActive must have pushed account 1 onto the wallet service.
	if fw.gotAccountIndex != 1 {
		t.Fatalf("wallet bound to account %d, want 1", fw.gotAccountIndex)
	}
}

func TestSelectAccountUnknown(t *testing.T) {
	v := multiAccountVault()
	h := multiAcctHandler(v, &fakeWallet{set: true})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodPost, "/wallet/account/select", strings.NewReader(`{"account_index":9}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("select underived account = %d, want 404 (body=%q)", rec.Code, rec.Body.String())
	}
}

func TestSelectAccountNoActiveWallet(t *testing.T) {
	v := &fakeVault{exists: true, locked: false}
	h := multiAcctHandler(v, &fakeWallet{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodPost, "/wallet/account/select", strings.NewReader(`{"account_index":0}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("select without active wallet = %d, want 409", rec.Code)
	}
}

func TestAddAccount(t *testing.T) {
	v := multiAccountVault()
	h := multiAcctHandler(v, &fakeWallet{set: true})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodPost, "/wallet/accounts",
		strings.NewReader(`{"account_index":2,"vault_password":"vault-pass","spend_password":"spend-pass"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("add account = %d body=%q", rec.Code, rec.Body.String())
	}
	if v.gotVault != "vault-pass" || v.gotSpend != "spend-pass" {
		t.Fatalf("AddAccount got vault=%q spend=%q", v.gotVault, v.gotSpend)
	}
	if !strings.Contains(rec.Body.String(), `"index":2`) {
		t.Fatalf("add account response missing new account: %s", rec.Body.String())
	}
}

func TestAddAccountValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing spend", `{"account_index":2,"vault_password":"vault-pass"}`},
		{"missing vault", `{"account_index":2,"spend_password":"spend-pass"}`},
		{"hardened index", `{"account_index":2147483648,"vault_password":"v","spend_password":"s"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := multiAccountVault()
			h := multiAcctHandler(v, &fakeWallet{set: true})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, localReq(http.MethodPost, "/wallet/accounts", strings.NewReader(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400 (body=%q)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}
