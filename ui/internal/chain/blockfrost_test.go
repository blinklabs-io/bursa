package chain

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
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
		_, _ = w.Write([]byte(`{"stake_address":"stake_test1xyz","active":true,"registered":true,"active_epoch":42,"controlled_amount":"1500000","rewards_sum":"2000","withdrawals_sum":"0","reserves_sum":"0","treasury_sum":"0","withdrawable_amount":"2000","pool_id":"pool1abc"}`))
	})
	got, err := c.Account(context.Background(), "stake_test1xyz")
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if got.ControlledAmount != "1500000" || got.PoolID == nil || *got.PoolID != "pool1abc" || got.DRepID != nil || !got.Active || !got.Registered {
		t.Fatalf("unexpected account: %+v", got)
	}
}

func TestAccountDRepIDFromDingoMetadata(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "metadata.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE account (
		credential_tag integer NOT NULL,
		staking_key blob NOT NULL,
		drep blob,
		drep_type integer,
		active boolean NOT NULL
	)`)
	if err != nil {
		t.Fatalf("create account table: %v", err)
	}
	stakingKey := make([]byte, lcommon.AddressHashSize)
	for i := range stakingKey {
		stakingKey[i] = byte(i + 1)
	}
	stakeAddr, err := lcommon.NewAddressFromParts(lcommon.AddressTypeNoneKey, lcommon.AddressNetworkTestnet, nil, stakingKey)
	if err != nil {
		t.Fatalf("stake address: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO account (credential_tag, staking_key, drep, drep_type, active) VALUES (?, ?, NULL, ?, 1)`,
		dingoAccountCredentialKeyHash,
		stakingKey,
		dingoDRepTypeAlwaysAbstain,
	)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}

	c := NewClientURL("http://127.0.0.1:1", WithDingoDataDir(dir))
	got, err := c.AccountDRepID(context.Background(), stakeAddr.String())
	if err != nil {
		t.Fatalf("AccountDRepID: %v", err)
	}
	if got == nil || *got != "drep_abstain" {
		t.Fatalf("AccountDRepID = %v, want drep_abstain", got)
	}
}

func TestDingoDRepID(t *testing.T) {
	hash := make([]byte, lcommon.AddressHashSize)
	for i := range hash {
		hash[i] = 0xaa
	}
	got, ok, err := dingoDRepID(hash, dingoDRepTypeAddrKeyHash)
	if err != nil || !ok || !strings.HasPrefix(got, "drep-keyHash-") {
		t.Fatalf("key hash drep = %q, ok=%v, err=%v", got, ok, err)
	}
	got, ok, err = dingoDRepID(hash, dingoDRepTypeScriptHash)
	if err != nil || !ok || !strings.HasPrefix(got, "drep-scriptHash-") {
		t.Fatalf("script hash drep = %q, ok=%v, err=%v", got, ok, err)
	}
	got, ok, err = dingoDRepID(nil, dingoDRepTypeAlwaysAbstain)
	if err != nil || !ok || got != "drep_abstain" {
		t.Fatalf("abstain drep = %q, ok=%v, err=%v", got, ok, err)
	}
	got, ok, err = dingoDRepID(nil, dingoDRepTypeNoConfidence)
	if err != nil || !ok || got != "drep_no_confidence" {
		t.Fatalf("no-confidence drep = %q, ok=%v, err=%v", got, ok, err)
	}
	got, ok, err = dingoDRepID(nil, dingoDRepTypeAddrKeyHash)
	if err != nil || ok || got != "" {
		t.Fatalf("nil key drep = %q, ok=%v, err=%v", got, ok, err)
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

func TestProtocolParams(t *testing.T) {
	drepDeposit := "500000000"
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/epochs/latest/parameters" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_deposit":"2000000","pool_deposit":"500000000","drep_deposit":"500000000"}`))
	})
	got, err := c.ProtocolParams(context.Background())
	if err != nil {
		t.Fatalf("ProtocolParams: %v", err)
	}
	if got.KeyDeposit != "2000000" || got.PoolDeposit != "500000000" {
		t.Fatalf("unexpected params: %+v", got)
	}
	if got.DRepDeposit == nil || *got.DRepDeposit != drepDeposit {
		t.Fatalf("drep_deposit = %v, want %q", got.DRepDeposit, drepDeposit)
	}
}

func TestProtocolParamsPreConwayDRepDepositNull(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"key_deposit":"2000000","pool_deposit":"500000000","drep_deposit":null}`))
	})
	got, err := c.ProtocolParams(context.Background())
	if err != nil {
		t.Fatalf("ProtocolParams: %v", err)
	}
	if got.DRepDeposit != nil {
		t.Fatalf("drep_deposit = %v, want nil", got.DRepDeposit)
	}
}

func TestPoolFiltersExtendedList(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/pools/extended" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"pool_id":"pool1aaa","hex":"aa","margin_cost":0.05,"declared_pledge":"100000000","fixed_cost":"340000000","live_stake":"5000000000","active_stake":"4800000000"},
			{"pool_id":"pool1bbb","hex":"bb","margin_cost":0.02,"declared_pledge":"200000000","fixed_cost":"170000000","live_stake":"9000000000","active_stake":"8800000000"}
		]`))
	})
	got, err := c.Pool(context.Background(), "pool1bbb")
	if err != nil {
		t.Fatalf("Pool: %v", err)
	}
	if got.PoolID != "pool1bbb" || got.MarginCost != 0.02 || got.FixedCost != "170000000" || got.DeclaredPledge != "200000000" {
		t.Fatalf("unexpected pool: %+v", got)
	}
}

func TestPoolStopsWhenMatchFoundBeforeLastPage(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v0/pools/extended" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if page := r.URL.Query().Get("page"); page != "1" {
			t.Fatalf("requested page %q after match was on page 1", page)
		}
		rows := make([]PoolInfo, pageSize)
		for i := range rows {
			rows[i] = PoolInfo{PoolID: fmt.Sprintf("pool1%03d", i)}
		}
		rows[7] = PoolInfo{PoolID: "pool1target", FixedCost: "340000000"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rows); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	})
	got, err := c.Pool(context.Background(), "pool1target")
	if err != nil {
		t.Fatalf("Pool: %v", err)
	}
	if got.PoolID != "pool1target" || got.FixedCost != "340000000" {
		t.Fatalf("unexpected pool: %+v", got)
	}
	if calls != 1 {
		t.Fatalf("requests = %d, want 1", calls)
	}
}

func TestPoolUsesCachedCompleteList(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"pool_id":"pool1aaa","fixed_cost":"340000000"},
			{"pool_id":"pool1bbb","fixed_cost":"170000000"}
		]`))
	})
	if _, err := c.Pool(context.Background(), "pool1bbb"); err != nil {
		t.Fatalf("Pool first lookup: %v", err)
	}
	got, err := c.Pool(context.Background(), "pool1aaa")
	if err != nil {
		t.Fatalf("Pool cached lookup: %v", err)
	}
	if got.FixedCost != "340000000" {
		t.Fatalf("unexpected cached pool: %+v", got)
	}
	if calls != 1 {
		t.Fatalf("requests = %d, want 1", calls)
	}
}

func TestPoolNotInList(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"pool_id":"pool1aaa"}]`))
	})
	_, err := c.Pool(context.Background(), "pool1missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("a pool not in the list should map to ErrNotFound, got %v", err)
	}
}

func TestDRep(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/governance/dreps/drep1abc" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"drep_id":"drep1abc","hex":"abc","has_script":false,"registered":true,"amount":"123","active":true,"live_stake":"123"}`))
	})
	got, err := c.DRep(context.Background(), "drep1abc")
	if err != nil {
		t.Fatalf("DRep: %v", err)
	}
	if got.DRepID != "drep1abc" || !got.Registered || !got.Active {
		t.Fatalf("unexpected drep: %+v", got)
	}
}

func TestDRepNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v0/governance/dreps/drep1missing" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(blockfrostNotFoundJSON))
	})
	_, err := c.DRep(context.Background(), "drep1missing")
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

func TestGenesis(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/genesis" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"epoch_length":432000,"slots_per_kes_period":129600,"slot_length":1,"max_kes_evolutions":62,"network_magic":2}`))
	})
	got, err := c.Genesis(context.Background())
	if err != nil {
		t.Fatalf("Genesis: %v", err)
	}
	if got.SlotsPerKESPeriod != 129600 || got.EpochLength != 432000 || got.MaxKESEvolutions != 62 {
		t.Fatalf("unexpected genesis: %+v", got)
	}
	if got.SlotLength != 1 || got.NetworkMagic != 2 {
		t.Fatalf("genesis SlotLength/NetworkMagic: got %+v", got)
	}
}

func TestLatestEpoch(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/epochs/latest" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"epoch":512,"start_time":1700000000,"end_time":1700432000}`))
	})
	got, err := c.LatestEpoch(context.Background())
	if err != nil {
		t.Fatalf("LatestEpoch: %v", err)
	}
	if got.Epoch != 512 {
		t.Fatalf("epoch = %d, want 512", got.Epoch)
	}
	if got.StartTime != 1700000000 || got.EndTime != 1700432000 {
		t.Fatalf("epoch times: got StartTime=%d EndTime=%d, want 1700000000/1700432000", got.StartTime, got.EndTime)
	}
}
