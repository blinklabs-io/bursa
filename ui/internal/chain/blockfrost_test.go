package chain

import (
	"context"
	"database/sql"
	"encoding/hex"
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

func TestAccountRewardsType(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v0/accounts/stake_test1xyz/rewards" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// First row reports a reward type, second omits the field entirely.
		_, _ = w.Write([]byte(`[
			{"epoch":42,"amount":"2000","pool_id":"pool1abc","type":"member"},
			{"epoch":43,"amount":"3000","pool_id":"pool1abc"}
		]`))
	})
	got, err := c.AccountRewards(context.Background(), "stake_test1xyz")
	if err != nil {
		t.Fatalf("AccountRewards: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Type != "member" {
		t.Fatalf("got[0].Type = %q, want member", got[0].Type)
	}
	if got[1].Type != "" {
		t.Fatalf("got[1].Type = %q, want empty (type omitted)", got[1].Type)
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

func TestPoolsReturnsFullList(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v0/pools/extended" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"pool_id":"pool1aaa","hex":"aa","margin_cost":0.05,"live_stake":"5000000000","live_saturation":0.42},
			{"pool_id":"pool1bbb","hex":"bb","margin_cost":0.02,"live_stake":"9000000000","live_saturation":0.90}
		]`))
	})
	got, err := c.Pools(context.Background())
	if err != nil {
		t.Fatalf("Pools: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Pools returned %d pools, want 2", len(got))
	}
	if got[1].PoolID != "pool1bbb" || got[1].LiveSaturation != 0.90 || got[1].LiveStake != "9000000000" {
		t.Fatalf("pool[1] = %+v, want pool1bbb / saturation 0.90 / live 9000000000", got[1])
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

func TestDRepsFromNodeList(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/governance/dreps" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("count"); got != fmt.Sprintf("%d", pageSize) {
			t.Errorf("count = %q, want %d", got, pageSize)
		}
		w.Header().Set("Content-Type", "application/json")
		// Shape of dingo's GET /api/v0/governance/dreps list: CIP-129
		// drep_id, 29-byte hex payload, epoch-based retired/expired status
		// and a resolved CIP-119 anchor document. Note there is no "active"
		// or "registered" field — status is derived from retired/expired.
		_, _ = w.Write([]byte(`[
			{"drep_id":"drep1aaa","hex":"22aaaa","amount":"1500000","has_script":false,"retired":false,"expired":false,"last_active_epoch":42,"metadata":{"url":"https://example.com/drep.json","hash":"cafe","json_metadata":{"body":{"givenName":"A"}},"bytes":"00"}},
			{"drep_id":"drep1bbb","hex":"23bbbb","amount":"0","has_script":true,"retired":true,"expired":false,"last_active_epoch":null,"metadata":null},
			{"drep_id":"drep_always_abstain","hex":"","amount":"7000000","has_script":false,"retired":false,"expired":false,"last_active_epoch":null,"metadata":null}
		]`))
	})
	got, err := c.DReps(context.Background())
	if err != nil {
		t.Fatalf("DReps: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("DReps returned %d dreps, want 3", len(got))
	}

	a := got[0]
	if a.DRepID != "drep1aaa" || a.Hex != "22aaaa" || a.HasScript {
		t.Fatalf("drep[0] = %+v, want the key-hash drep1aaa entry", a)
	}
	if a.Amount != "1500000" {
		t.Fatalf("drep[0] voting power = %q, want 1500000", a.Amount)
	}
	if a.Retired || a.Expired {
		t.Fatalf("drep[0] = %+v, want neither retired nor expired", a)
	}
	if a.LastActiveEpoch == nil || *a.LastActiveEpoch != 42 {
		t.Fatalf("drep[0] last active epoch = %v, want 42", a.LastActiveEpoch)
	}
	if a.Metadata == nil || a.Metadata.URL != "https://example.com/drep.json" {
		t.Fatalf("drep[0] metadata = %+v, want the anchor url", a.Metadata)
	}
	if a.Metadata.Hash != "cafe" {
		t.Fatalf("drep[0] metadata hash = %q, want cafe", a.Metadata.Hash)
	}

	b := got[1]
	if !b.Retired || !b.HasScript {
		t.Fatalf("drep[1] = %+v, want a retired script-hash drep", b)
	}
	if b.LastActiveEpoch != nil {
		t.Fatalf("drep[1] last active epoch = %v, want nil", b.LastActiveEpoch)
	}
	if b.Metadata != nil {
		t.Fatalf("drep[1] metadata = %+v, want nil for a drep with no anchor", b.Metadata)
	}

	// The predefined targets are part of the node's list (interleaved at the
	// position of their first delegation) and carry real voting power. The
	// client passes them through; the directory screen decides how to render
	// them.
	p := got[2]
	if p.DRepID != "drep_always_abstain" || p.Hex != "" || p.Amount != "7000000" {
		t.Fatalf("drep[2] = %+v, want the predefined abstain entry with its voting power", p)
	}
}

func TestDRepsPagesThroughNodeList(t *testing.T) {
	pages := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		pages++
		if r.URL.Path != "/api/v0/governance/dreps" {
			t.Errorf("path = %q", r.URL.Path)
		}
		rows := []DRepListItem{{DRepID: "drep1last"}}
		if r.URL.Query().Get("page") == "1" {
			rows = make([]DRepListItem, pageSize)
			for i := range rows {
				rows[i] = DRepListItem{DRepID: fmt.Sprintf("drep1%03d", i)}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rows); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	})
	got, err := c.DReps(context.Background())
	if err != nil {
		t.Fatalf("DReps: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Fatalf("DReps returned %d dreps, want %d across both pages", len(got), pageSize+1)
	}
	if got[pageSize].DRepID != "drep1last" {
		t.Fatalf("last drep = %q, want the page-2 entry", got[pageSize].DRepID)
	}
	if pages != 2 {
		t.Fatalf("requests = %d, want 2", pages)
	}
}

// The directory reads the node's HTTP list, so it must work with no Dingo data
// directory configured — it no longer opens Dingo's private metadata schema.
func TestDRepsWithoutDingoDataDir(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"drep_id":"drep1aaa","hex":"22aaaa","amount":"1","metadata":null}]`))
	})
	got, err := c.DReps(context.Background())
	if err != nil {
		t.Fatalf("DReps: %v", err)
	}
	if len(got) != 1 || got[0].DRepID != "drep1aaa" {
		t.Fatalf("DReps = %+v, want the node's single entry without a data dir", got)
	}
}

func TestAsset(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/assets/policy123746f6b656e" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"asset":"policy123746f6b656e","policy_id":"policy123","asset_name":"746f6b656e","asset_name_ascii":"token","fingerprint":"asset1xyz","quantity":"1000000","initial_mint_tx_hash":"aa","mint_or_burn_count":1,"onchain_metadata":{"name":"Token","ticker":"TOK","decimals":6}}`))
	})
	got, err := c.Asset(context.Background(), "policy123746f6b656e")
	if err != nil {
		t.Fatalf("Asset: %v", err)
	}
	if got.Asset != "policy123746f6b656e" || got.PolicyID != "policy123" || got.AssetName != "746f6b656e" {
		t.Fatalf("unexpected asset: %+v", got)
	}
	if got.AssetNameASCII != "token" || got.Fingerprint != "asset1xyz" || got.Quantity != "1000000" {
		t.Fatalf("unexpected asset: %+v", got)
	}
	if got.OnchainMetadata == nil {
		t.Fatalf("OnchainMetadata = nil, want raw JSON")
	}
	var meta struct {
		Name     string `json:"name"`
		Ticker   string `json:"ticker"`
		Decimals int    `json:"decimals"`
	}
	if err := json.Unmarshal(got.OnchainMetadata, &meta); err != nil {
		t.Fatalf("unmarshal OnchainMetadata: %v", err)
	}
	if meta.Name != "Token" || meta.Ticker != "TOK" || meta.Decimals != 6 {
		t.Fatalf("unexpected onchain metadata: %+v", meta)
	}
}

func TestAssetNilMetadata(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"asset":"policy123746f6b656e","policy_id":"policy123","asset_name":"746f6b656e","asset_name_ascii":"token","fingerprint":"asset1xyz","quantity":"1000000","initial_mint_tx_hash":"","mint_or_burn_count":0,"onchain_metadata":null}`))
	})
	got, err := c.Asset(context.Background(), "policy123746f6b656e")
	if err != nil {
		t.Fatalf("Asset: %v", err)
	}
	// dingo's current adapter always reports onchain_metadata: null — this must
	// decode cleanly (as the raw JSON literal "null", which the frontend reads
	// as a falsy value) rather than erroring, since it is the common case today.
	if string(got.OnchainMetadata) != "null" {
		t.Fatalf("OnchainMetadata = %s, want the raw JSON null literal", got.OnchainMetadata)
	}
}

func TestAssetEnrichesNilMetadataFromDingoCIP25Index(t *testing.T) {
	const (
		policyID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		nameHex  = "746f6b656e"
		unit     = policyID + nameHex
	)
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "metadata.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE utxo (
		id integer PRIMARY KEY,
		transaction_id integer,
		deleted_slot integer NOT NULL
	);
	CREATE TABLE asset (
		id integer PRIMARY KEY,
		utxo_id integer NOT NULL,
		policy_id blob NOT NULL,
		name blob NOT NULL
	);
	CREATE INDEX idx_asset_policy_id ON asset(policy_id);
	CREATE TABLE transaction_metadata_label (
		id integer PRIMARY KEY,
		transaction_id integer NOT NULL,
		label integer NOT NULL,
		slot integer NOT NULL,
		cbor_value blob,
		json_value text NOT NULL
	);
	CREATE UNIQUE INDEX idx_tx_metadata_label_tx_label
		ON transaction_metadata_label(transaction_id, label)`)
	if err != nil {
		t.Fatalf("create metadata tables: %v", err)
	}
	policyIDBytes, err := hex.DecodeString(policyID)
	if err != nil {
		t.Fatalf("decode policy ID: %v", err)
	}
	name, err := hex.DecodeString(nameHex)
	if err != nil {
		t.Fatalf("decode asset name: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO utxo (id, transaction_id, deleted_slot)
		 VALUES (1, 1, 99), (2, 2, 0);
		 INSERT INTO asset (id, utxo_id, policy_id, name)
		 VALUES (1, 1, ?, ?), (2, 2, ?, ?)`,
		policyIDBytes, name,
		policyIDBytes, name,
	)
	if err != nil {
		t.Fatalf("insert asset outputs: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO transaction_metadata_label
			(id, transaction_id, label, slot, json_value)
		 VALUES
			(1, 1, 721, 10, ?),
			(2, 2, 721, 20, ?),
			(3, 3, 20,  30, ?),
			(4, 4, 721, 40, ?)`,
		`{"`+policyID+`":{"token":{"name":"Old","image":"ipfs://old"}}}`,
		`{"`+policyID+`":{"`+nameHex+`":{"name":"Current","image":"ipfs://current"}}}`,
		`{"`+policyID+`":{"`+nameHex+`":{"name":"Wrong label"}}}`,
		`{"`+policyID+`":{"`+nameHex+`":{"name":"Unrelated transaction"}}}`,
	)
	if err != nil {
		t.Fatalf("insert metadata: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v0/assets/"+unit {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"asset":%q,"policy_id":%q,"asset_name":%q,"asset_name_ascii":"token","onchain_metadata":null}`,
			unit, policyID, nameHex,
		)
	}))
	defer srv.Close()

	c := NewClientURL(srv.URL, WithDingoDataDir(dir))
	got, err := c.Asset(context.Background(), unit)
	if err != nil {
		t.Fatalf("Asset: %v", err)
	}
	var metadata struct {
		Name  string `json:"name"`
		Image string `json:"image"`
	}
	if err := json.Unmarshal(got.OnchainMetadata, &metadata); err != nil {
		t.Fatalf("unmarshal enriched metadata: %v", err)
	}
	if metadata.Name != "Current" || metadata.Image != "ipfs://current" {
		t.Fatalf("OnchainMetadata = %+v, want latest producing-transaction CIP-25 entry", metadata)
	}
}

func TestAssetMissingDingoMetadataIndexKeepsNullMetadata(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "metadata.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"asset":"policy123746f6b656e",
			"policy_id":"policy123",
			"asset_name":"746f6b656e",
			"onchain_metadata":null
		}`))
	})
	c.dingoDataDir = dir
	got, err := c.Asset(context.Background(), "policy123746f6b656e")
	if err != nil {
		t.Fatalf("Asset: %v", err)
	}
	if string(got.OnchainMetadata) != "null" {
		t.Fatalf("OnchainMetadata = %s, want null", got.OnchainMetadata)
	}
}

func TestAssetCIP25MetadataPreservesContextCancellation(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "metadata.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewClientURL("http://127.0.0.1:1", WithDingoDataDir(dir))
	_, err = c.assetCIP25Metadata(
		ctx,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"746f6b656e",
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("assetCIP25Metadata error = %v, want context.Canceled", err)
	}
}

func TestExtractCIP25AssetMetadataAcceptsUTF8V1Name(t *testing.T) {
	const policyID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	got := extractCIP25AssetMetadata(
		json.RawMessage(`{"`+policyID+`":{"Token":{"name":"Version one"}}}`),
		policyID,
		"546f6b656e",
	)
	var metadata struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(got, &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata.Name != "Version one" {
		t.Fatalf("name = %q, want Version one", metadata.Name)
	}
}

func TestAssetNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v0/assets/policymissing" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(blockfrostNotFoundJSON))
	})
	_, err := c.Asset(context.Background(), "policymissing")
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

func TestAssetAddresses(t *testing.T) {
	const asset = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a6368726973"
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/assets/"+asset+"/addresses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"address":"addr1abc","quantity":"1"}]`))
	})
	got, err := c.AssetAddresses(context.Background(), asset)
	if err != nil {
		t.Fatalf("AssetAddresses: %v", err)
	}
	if len(got) != 1 || got[0].Address != "addr1abc" || got[0].Quantity != "1" {
		t.Fatalf("unexpected asset addresses: %+v", got)
	}
}

func TestAssetAddressesNotFound(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v0/assets/deadbeef/addresses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(blockfrostNotFoundJSON))
	})
	_, err := c.AssetAddresses(context.Background(), "deadbeef")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 should map to ErrNotFound, got %v", err)
	}
}

func TestAssetAddressesPaginated(t *testing.T) {
	const asset = "deadbeef"
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v0/assets/"+asset+"/addresses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("count") != "100" {
			t.Errorf("count = %q", q.Get("count"))
		}
		var rows []string
		switch q.Get("page") {
		case "1":
			for i := range pageSize {
				rows = append(rows, fmt.Sprintf(`{"address":"addr1_%03d","quantity":"1"}`, i))
			}
		case "2":
			rows = append(rows, `{"address":"addr1_100","quantity":"1"}`)
		default:
			t.Errorf("page = %q", q.Get("page"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("[" + strings.Join(rows, ",") + "]"))
	})
	got, err := c.AssetAddresses(context.Background(), asset)
	if err != nil {
		t.Fatalf("AssetAddresses: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Fatalf("len = %d, want %d", len(got), pageSize+1)
	}
}

// govProposalDDL and govVoteDDL mirror the subset of Dingo's metadata schema
// (models.GovernanceProposal / models.GovernanceVote) that GovernanceActions
// reads.
const govProposalDDL = `CREATE TABLE governance_proposal (
	id integer PRIMARY KEY,
	tx_hash blob NOT NULL,
	action_index integer NOT NULL,
	action_type integer NOT NULL,
	proposed_epoch integer NOT NULL,
	expires_epoch integer NOT NULL,
	enacted_epoch integer,
	ratified_epoch integer,
	expired_epoch integer,
	anchor_url text,
	deposit integer NOT NULL,
	deleted_slot integer
)`

const govVoteDDL = `CREATE TABLE governance_vote (
	id integer PRIMARY KEY,
	proposal_id integer NOT NULL,
	vote integer NOT NULL,
	deleted_slot integer
)`

func TestGovernanceActionsFromDingoMetadata(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "metadata.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(govProposalDDL); err != nil {
		t.Fatalf("create governance_proposal: %v", err)
	}
	if _, err := db.Exec(govVoteDDL); err != nil {
		t.Fatalf("create governance_vote: %v", err)
	}

	txHash := make([]byte, 32)
	for i := range txHash {
		txHash[i] = byte(i + 1)
	}
	// An active info action (type 6) in epoch 100, still open.
	if _, err := db.Exec(
		`INSERT INTO governance_proposal
		 (id, tx_hash, action_index, action_type, proposed_epoch, expires_epoch, anchor_url, deposit)
		 VALUES (1, ?, 0, ?, 100, 130, ?, 100000000000)`,
		txHash, lcommon.GovActionTypeInfo, "https://example.test/info.json",
	); err != nil {
		t.Fatalf("insert active proposal: %v", err)
	}
	// An enacted treasury-withdrawal (type 2) in an earlier epoch.
	otherHash := make([]byte, 32)
	for i := range otherHash {
		otherHash[i] = byte(0xA0 + i)
	}
	if _, err := db.Exec(
		`INSERT INTO governance_proposal
		 (id, tx_hash, action_index, action_type, proposed_epoch, expires_epoch, enacted_epoch, anchor_url, deposit)
		 VALUES (2, ?, 3, ?, 90, 120, 95, '', 100000000000)`,
		otherHash, lcommon.GovActionTypeTreasuryWithdrawal,
	); err != nil {
		t.Fatalf("insert enacted proposal: %v", err)
	}
	// A soft-deleted (rolled-back) proposal must be excluded.
	if _, err := db.Exec(
		`INSERT INTO governance_proposal
		 (id, tx_hash, action_index, action_type, proposed_epoch, expires_epoch, anchor_url, deposit, deleted_slot)
		 VALUES (3, ?, 0, ?, 80, 110, '', 100000000000, 42)`,
		txHash, lcommon.GovActionTypeInfo,
	); err != nil {
		t.Fatalf("insert deleted proposal: %v", err)
	}
	// Votes for proposal 1: 2 Yes, 1 No, 1 Abstain (+ a rolled-back Yes ignored).
	for _, v := range []struct {
		vote    int
		deleted any
	}{{1, nil}, {1, nil}, {0, nil}, {2, nil}, {1, 42}} {
		if _, err := db.Exec(
			`INSERT INTO governance_vote (proposal_id, vote, deleted_slot) VALUES (1, ?, ?)`,
			v.vote, v.deleted,
		); err != nil {
			t.Fatalf("insert vote: %v", err)
		}
	}

	c := NewClientURL("http://127.0.0.1:1", WithDingoDataDir(dir))
	got, err := c.GovernanceActions(context.Background())
	if err != nil {
		t.Fatalf("GovernanceActions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (deleted excluded)", len(got))
	}
	// Ordered by proposed_epoch DESC: proposal 1 (epoch 100) first.
	a := got[0]
	if a.Type != "info" || a.Status != "active" || a.ProposedEpoch != 100 {
		t.Fatalf("action[0] = %+v, want info/active/epoch100", a)
	}
	if a.YesVotes != 2 || a.NoVotes != 1 || a.AbstainVotes != 1 {
		t.Fatalf("action[0] tallies = %d/%d/%d, want 2/1/1", a.YesVotes, a.NoVotes, a.AbstainVotes)
	}
	if a.AnchorURL != "https://example.test/info.json" || a.Deposit != "100000000000" {
		t.Fatalf("action[0] anchor/deposit = %q/%q", a.AnchorURL, a.Deposit)
	}
	if !strings.HasPrefix(a.ActionID, "gov_action1") {
		t.Fatalf("action[0] id = %q, want CIP-129 gov_action1… bech32", a.ActionID)
	}
	if a.TxHash != hex.EncodeToString(txHash) {
		t.Fatalf("action[0] tx_hash = %q", a.TxHash)
	}
	if got[1].Type != "treasury-withdrawal" || got[1].Status != "enacted" {
		t.Fatalf("action[1] = %+v, want treasury-withdrawal/enacted", got[1])
	}
	if got[1].YesVotes != 0 || got[1].NoVotes != 0 || got[1].AbstainVotes != 0 {
		t.Fatalf("action[1] tallies = %+v, want all zero", got[1])
	}
}

func TestGovernanceActionsNoDataDir(t *testing.T) {
	c := NewClientURL("http://127.0.0.1:1")
	got, err := c.GovernanceActions(context.Background())
	if err != nil {
		t.Fatalf("GovernanceActions: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0 with no data dir", len(got))
	}
}

func TestGovernanceActionsMissingTable(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "metadata.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// A metadata DB that exists but has no governance tables (partial backfill).
	if _, err := db.Exec(`CREATE TABLE account (id integer)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	db.Close()

	c := NewClientURL("http://127.0.0.1:1", WithDingoDataDir(dir))
	got, err := c.GovernanceActions(context.Background())
	if err != nil {
		t.Fatalf("GovernanceActions: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0 when governance tables absent", len(got))
	}
}

func TestGovActionStatus(t *testing.T) {
	valid := func(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }
	var unset sql.NullInt64

	tests := []struct {
		name    string
		enacted sql.NullInt64
		ratified,
		expired sql.NullInt64
		want string
	}{
		{"none set is active", unset, unset, unset, "active"},
		{"ratified only", unset, valid(10), unset, "ratified"},
		{"expired only", unset, unset, valid(10), "expired"},
		{"enacted only", valid(10), unset, unset, "enacted"},
		{"enacted takes priority over ratified and expired", valid(12), valid(11), valid(10), "enacted"},
		// A ratified action can still lapse into expired (e.g. it ratified but
		// never got enacted before its expiration epoch); expired must win so
		// the browser doesn't show a stale "ratified" status.
		{"expired takes priority over ratified", unset, valid(10), valid(11), "expired"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := govActionStatus(tc.enacted, tc.ratified, tc.expired)
			if got != tc.want {
				t.Fatalf("govActionStatus(%v, %v, %v) = %q, want %q", tc.enacted, tc.ratified, tc.expired, got, tc.want)
			}
		})
	}
}

// TestGovernanceActionsSkipsUnknownVoteKind covers a Dingo that has added a
// vote choice this build does not know. The screen is a read-only browser over
// node-local data, so one unrecognized vote must not fail the whole query —
// that would surface as a 503 and blank the governance screen entirely. The
// known tallies still have to be right.
func TestGovernanceActionsSkipsUnknownVoteKind(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "metadata.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(govProposalDDL); err != nil {
		t.Fatalf("create governance_proposal: %v", err)
	}
	if _, err := db.Exec(govVoteDDL); err != nil {
		t.Fatalf("create governance_vote: %v", err)
	}

	txHash := make([]byte, 32)
	for i := range txHash {
		txHash[i] = byte(i + 1)
	}
	if _, err := db.Exec(
		`INSERT INTO governance_proposal
		 (id, tx_hash, action_index, action_type, proposed_epoch, expires_epoch, anchor_url, deposit)
		 VALUES (1, ?, 0, ?, 100, 130, '', 100000000000)`,
		txHash, lcommon.GovActionTypeInfo,
	); err != nil {
		t.Fatalf("insert proposal: %v", err)
	}
	// One Yes, one No, and two of a kind from the future.
	for _, vote := range []int{1, 0, 7, 7} {
		if _, err := db.Exec(
			`INSERT INTO governance_vote (proposal_id, vote, deleted_slot) VALUES (1, ?, NULL)`,
			vote,
		); err != nil {
			t.Fatalf("insert vote: %v", err)
		}
	}

	c := NewClientURL("http://127.0.0.1:1", WithDingoDataDir(dir))
	got, err := c.GovernanceActions(context.Background())
	if err != nil {
		t.Fatalf("GovernanceActions with an unknown vote kind: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1", len(got))
	}
	if got[0].YesVotes != 1 || got[0].NoVotes != 1 || got[0].AbstainVotes != 0 {
		t.Fatalf("tallies = yes %d no %d abstain %d, want 1/1/0 with the unknown kind skipped",
			got[0].YesVotes, got[0].NoVotes, got[0].AbstainVotes)
	}
}
