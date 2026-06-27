package chain

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const blockfrostNotFoundJSON = `{"status_code":404,"error":"Not Found","message":"The requested component has not been found."}`

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClientURL(srv.URL)
}

func TestAccount(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1xyz" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stake_address":"stake_test1xyz","active":true,"active_epoch":42,"controlled_amount":"1500000","rewards_sum":"2000","withdrawals_sum":"0","reserves_sum":"0","treasury_sum":"0","withdrawable_amount":"2000","pool_id":"pool1abc"}`))
	})
	got, err := c.Account(context.Background(), "stake_test1xyz")
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if got.ControlledAmount != "1500000" || got.PoolID == nil || *got.PoolID != "pool1abc" || !got.Active {
		t.Fatalf("unexpected account: %+v", got)
	}
}

func TestAccountAddresses(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1xyz/addresses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"address":"addr_test1a"},{"address":"addr_test1b"}]`))
	})
	got, err := c.AccountAddresses(context.Background(), "stake_test1xyz")
	if err != nil {
		t.Fatalf("AccountAddresses: %v", err)
	}
	if len(got) != 2 || got[0] != "addr_test1a" || got[1] != "addr_test1b" {
		t.Fatalf("unexpected addresses: %v", got)
	}
}

func TestAccountAddressesPaginated(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1xyz/addresses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("count") != "100" {
			t.Errorf("count = %q", q.Get("count"))
		}
		var rows []string
		switch q.Get("page") {
		case "1":
			for i := range 100 {
				rows = append(rows, fmt.Sprintf(`{"address":"addr_test1_%03d"}`, i))
			}
		case "2":
			for i := 100; i < 103; i++ {
				rows = append(rows, fmt.Sprintf(`{"address":"addr_test1_%03d"}`, i))
			}
		default:
			t.Errorf("page = %q", q.Get("page"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("[" + strings.Join(rows, ",") + "]"))
	})
	got, err := c.AccountAddresses(context.Background(), "stake_test1xyz")
	if err != nil {
		t.Fatalf("AccountAddresses: %v", err)
	}
	if len(got) != 103 {
		t.Fatalf("len = %d, want 103", len(got))
	}
	for i, addr := range got {
		if want := fmt.Sprintf("addr_test1_%03d", i); addr != want {
			t.Fatalf("got[%d] = %q, want %q", i, addr, want)
		}
	}
}

func TestGetAllPagesLimitExceeded(t *testing.T) {
	requests := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1xyz/addresses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		requests++
		rows := make([]string, 0, pageSize)
		for i := range pageSize {
			rows = append(rows, fmt.Sprintf(`{"address":"addr_test1_%03d"}`, i))
		}
		_, _ = w.Write([]byte("[" + strings.Join(rows, ",") + "]"))
	})
	_, err := getAllPagesLimit[accountAddress](context.Background(), c, "/api/v0/accounts/stake_test1xyz/addresses", 2)
	if !errors.Is(err, errPageLimitExceeded) {
		t.Fatalf("getAllPagesLimit err = %v, want errPageLimitExceeded", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestAddressUTxOs(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/addresses/addr_test1a/utxos" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"address":"addr_test1a","tx_hash":"aa","output_index":0,"amount":[{"unit":"lovelace","quantity":"1000000"},{"unit":"policytoken","quantity":"7"}],"block":"b1"}]`))
	})
	got, err := c.AddressUTxOs(context.Background(), "addr_test1a")
	if err != nil {
		t.Fatalf("AddressUTxOs: %v", err)
	}
	if len(got) != 1 || len(got[0].Amount) != 2 || got[0].Amount[1].Unit != "policytoken" || got[0].Amount[1].Quantity != "7" {
		t.Fatalf("unexpected utxos: %+v", got)
	}
}

func TestAddressTransactions(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/addresses/addr_test1a/transactions" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"tx_hash":"aa","tx_index":0,"block_height":100,"block_time":1700000000}]`))
	})
	got, err := c.AddressTransactions(context.Background(), "addr_test1a")
	if err != nil {
		t.Fatalf("AddressTransactions: %v", err)
	}
	if len(got) != 1 || got[0].TxHash != "aa" || got[0].BlockHeight != 100 || got[0].BlockTime != 1700000000 {
		t.Fatalf("unexpected txs: %+v", got)
	}
}

func TestAccountDelegations(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1xyz/delegations" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"active_epoch":42,"tx_hash":"aa","amount":"5000000","pool_id":"pool1abc"}]`))
	})
	got, err := c.AccountDelegations(context.Background(), "stake_test1xyz")
	if err != nil {
		t.Fatalf("AccountDelegations: %v", err)
	}
	if len(got) != 1 || got[0].ActiveEpoch != 42 || got[0].TxHash != "aa" || got[0].Amount != "5000000" || got[0].PoolID != "pool1abc" {
		t.Fatalf("unexpected delegations: %+v", got)
	}
}

func TestAccountDelegationsNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1missing/delegations" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(blockfrostNotFoundJSON))
	})
	_, err := c.AccountDelegations(context.Background(), "stake_test1missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

func TestAccountRewards(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1xyz/rewards" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"epoch":42,"amount":"2000","pool_id":"pool1abc"}]`))
	})
	got, err := c.AccountRewards(context.Background(), "stake_test1xyz")
	if err != nil {
		t.Fatalf("AccountRewards: %v", err)
	}
	if len(got) != 1 || got[0].Epoch != 42 || got[0].Amount != "2000" || got[0].PoolID != "pool1abc" {
		t.Fatalf("unexpected rewards: %+v", got)
	}
}

func TestAccountRewardsNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1missing/rewards" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(blockfrostNotFoundJSON))
	})
	_, err := c.AccountRewards(context.Background(), "stake_test1missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

func TestAsset(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/assets/policyAname1" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"asset":"policyAname1","policy_id":"policyA","asset_name":"6e616d6531","quantity":"1","onchain_metadata":{"name":"My NFT","image":"ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}}`))
	})
	got, err := c.Asset(context.Background(), "policyAname1")
	if err != nil {
		t.Fatalf("Asset: %v", err)
	}
	if got.Asset != "policyAname1" || got.PolicyID != "policyA" || got.Quantity != "1" {
		t.Fatalf("unexpected asset: %+v", got)
	}
	if len(got.OnchainMetadata) == 0 || !strings.Contains(string(got.OnchainMetadata), "ipfs://") {
		t.Fatalf("onchain_metadata not captured: %s", got.OnchainMetadata)
	}
}

func TestAssetNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v0/assets/policyMissing" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(blockfrostNotFoundJSON))
	})
	_, err := c.Asset(context.Background(), "policyMissing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

func TestErrorStatus(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/accounts/stake_test1missing" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(blockfrostNotFoundJSON))
	})
	_, err := c.Account(context.Background(), "stake_test1missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}
