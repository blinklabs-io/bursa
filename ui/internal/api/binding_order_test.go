package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blinklabs-io/bursa/ui/internal/connector"
	"github.com/blinklabs-io/bursa/ui/internal/supervisor"
	"github.com/blinklabs-io/bursa/ui/internal/vault"
	"github.com/blinklabs-io/bursa/ui/internal/wallet"
)

// bindingRecorder is a connector backend that records, each time the
// connector rebinds, which wallet the spend service was bound to then.
type bindingRecorder struct {
	fakeConnectorBackend
	sp    *fakeSpender
	calls []bindingCall
}

type bindingCall struct{ connector, spend string }

func (b *bindingRecorder) SetAccount(walletID string, _ *wallet.Account) {
	b.calls = append(b.calls, bindingCall{connector: walletID, spend: b.sp.gotID})
}

// A connector grant authorizes one wallet. While the connector still holds a
// wallet's identity, the services its operations call (addresses, signData,
// key export) must stay bound to that same wallet, or an existing grant
// briefly authorizes reads and signatures against the next one.
func TestConnectorIdentityNeverOutlivesTheServiceBinding(t *testing.T) {
	fv := &fakeVault{
		exists: true, locked: false,
		wallets: []vault.WalletMeta{
			{ID: "w1", Name: "one", Network: "preview", Account: sampleAccount("preview")},
			{ID: "w2", Name: "two", Network: "preview", Account: sampleAccount("preview")},
		},
	}
	sp := &fakeSpender{}
	rec := &bindingRecorder{sp: sp}
	h := NewHandler(
		testSessionToken,
		fakeStatuser{s: supervisor.Status{State: supervisor.StateReady}},
		fv,
		&fakeWallet{},
		sp,
		&fakeSettings{},
		&fakeContacts{},
		nil,
		&fakePoolOps{},
		nil,
		&fakeMultiSig{},
		"preview",
		http.NotFoundHandler(),
		WithConnector(connector.NewService(t.TempDir(), rec, nil)),
	)
	for _, path := range []string{"/wallet/w1/activate", "/wallet/w2/activate", "/vault/lock"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, localReq(http.MethodPost, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("POST %s = %d", path, w.Code)
		}
	}
	if len(rec.calls) == 0 {
		t.Fatal("connector was never rebound")
	}
	for k := 1; k < len(rec.calls); k++ {
		held := rec.calls[k-1]
		if held.connector == "" {
			continue
		}
		if held.spend != held.connector || rec.calls[k].spend != held.connector {
			t.Fatalf(
				"connector held %q while spend moved %q -> %q (calls %+v)",
				held.connector, held.spend, rec.calls[k].spend, rec.calls,
			)
		}
	}
}
