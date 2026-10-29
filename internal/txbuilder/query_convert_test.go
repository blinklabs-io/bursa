// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package txbuilder

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/mary"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
	"github.com/stretchr/testify/require"
)

func testQueryHash(b byte) lcommon.Blake2b224 {
	return lcommon.Blake2b224(bytes.Repeat([]byte{b}, 28))
}

func testQueryPoolID() lcommon.PoolId {
	return lcommon.PoolId(testQueryHash(0x33))
}

func testQueryHex(b byte, n int) string {
	return hex.EncodeToString(bytes.Repeat([]byte{b}, n))
}

func testQueryRewardAddress(
	t *testing.T,
	addrType uint8,
	networkID uint8,
	cred []byte,
) lcommon.Address {
	t.Helper()
	addr, err := lcommon.NewAddressFromParts(addrType, networkID, nil, cred)
	require.NoError(t, err)
	return addr
}

// testQueryPoolParams returns registered-pool parameters with a 5% margin and
// a testnet reward account.
func testQueryPoolParams(t *testing.T) *localstatequery.PoolStateParams {
	t.Helper()
	reward := testQueryRewardAddress(
		t,
		lcommon.AddressTypeNoneKey,
		lcommon.AddressNetworkTestnet,
		bytes.Repeat([]byte{0x11}, 28),
	)
	port := uint32(3001)
	host := "relay1.example.com"
	params := &localstatequery.PoolStateParams{
		Operator:      testQueryHash(0xaa),
		VrfKeyHash:    lcommon.Blake2b256(bytes.Repeat([]byte{0xbb}, 32)),
		Pledge:        1_000_000_000,
		Cost:          340_000_000,
		Margin:        &cbor.Rat{Rat: big.NewRat(1, 20)},
		RewardAccount: reward,
		PoolOwners:    []lcommon.Blake2b224{testQueryHash(0xcc), testQueryHash(0xdd)},
		Relays: []lcommon.PoolRelay{
			{
				Type:     lcommon.PoolRelayTypeSingleHostName,
				Port:     &port,
				Hostname: &host,
			},
		},
	}
	params.PoolMetadata = &struct {
		cbor.StructAsArray
		Url          string
		MetadataHash lcommon.PoolMetadataHash
	}{
		Url:          "https://pool.example.com/meta.json",
		MetadataHash: lcommon.PoolMetadataHash(bytes.Repeat([]byte{0xee}, 32)),
	}
	return params
}

func TestPoolQueryFromStateRegistered(t *testing.T) {
	poolID := testQueryPoolID()
	keyHash := lcommon.Blake2b224(poolID)
	ps := &localstatequery.PoolStateResult{
		PState: map[lcommon.Blake2b224]*localstatequery.PoolStateParams{
			keyHash: testQueryPoolParams(t),
		},
		FState:   map[lcommon.Blake2b224]*localstatequery.PoolStateParams{},
		Retiring: map[lcommon.Blake2b224]uint64{},
		Deposits: map[lcommon.Blake2b224]uint64{keyHash: 500_000_000},
	}
	counters := map[lcommon.Blake2b224]uint64{keyHash: 4}
	slot := uint64(129600*5 + 7)
	res, err := poolQueryFromState(
		poolID, ps, counters, slot, 129600, 62, 260, "preprod",
	)
	require.NoError(t, err)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	expected := `{
		"registered": true,
		"params": {
			"operator": "` + testQueryHex(0xaa, 28) + `",
			"vrf_key_hash": "` + testQueryHex(0xbb, 32) + `",
			"pledge": 1000000000,
			"cost": 340000000,
			"margin": "0.05",
			"margin_ratio": "1/20",
			"reward_account": "stake_test1uqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygxtxu2s",
			"owners": [
				"` + testQueryHex(0xcc, 28) + `",
				"` + testQueryHex(0xdd, 28) + `"
			],
			"relays": [
				{"type": 1, "port": 3001, "hostname": "relay1.example.com"}
			],
			"metadata_url": "https://pool.example.com/meta.json",
			"metadata_hash": "` + testQueryHex(0xee, 32) + `"
		},
		"deposit": 500000000,
		"opcert": {"on_chain_counter": 4, "next_counter": 5},
		"kes": {
			"current_slot": 648007,
			"slots_per_kes_period": 129600,
			"max_kes_evolutions": 62,
			"current_kes_period": 5
		},
		"epoch": 260
	}`
	require.JSONEq(t, expected, string(data))
}

// The reward account bech32 is built for --network, not copied from the
// network id the on-chain registration happens to carry.
func TestPoolQueryFromStateRewardAccountNetwork(t *testing.T) {
	poolID := testQueryPoolID()
	keyHash := lcommon.Blake2b224(poolID)
	for _, tc := range []struct {
		network  string
		addrType uint8
		cred     []byte
		expected string
	}{
		{
			"preprod",
			lcommon.AddressTypeNoneKey,
			bytes.Repeat([]byte{0x11}, 28),
			"stake_test1uqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygxtxu2s",
		},
		{
			"mainnet",
			lcommon.AddressTypeNoneKey,
			bytes.Repeat([]byte{0x11}, 28),
			"stake1uyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygppv7wd",
		},
		{
			"preprod",
			lcommon.AddressTypeNoneScript,
			bytes.Repeat([]byte{0x22}, 28),
			"stake_test17q3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs8a4sq7",
		},
		{
			"mainnet",
			lcommon.AddressTypeNoneScript,
			bytes.Repeat([]byte{0x22}, 28),
			"stake17y3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsqhljyr",
		},
	} {
		params := testQueryPoolParams(t)
		params.RewardAccount = testQueryRewardAddress(
			t, tc.addrType, lcommon.AddressNetworkTestnet, tc.cred,
		)
		ps := &localstatequery.PoolStateResult{
			PState: map[lcommon.Blake2b224]*localstatequery.PoolStateParams{
				keyHash: params,
			},
		}
		res, err := poolQueryFromState(
			poolID, ps, nil, 1000, 129600, 62, 260, tc.network,
		)
		require.NoError(t, err, tc.network)
		require.NotNil(t, res.Params, tc.network)
		require.Equal(t, tc.expected, res.Params.RewardAccount, tc.network)
	}
}

func TestPoolQueryFromStateUnregistered(t *testing.T) {
	poolID := testQueryPoolID()
	ps := &localstatequery.PoolStateResult{
		PState:   map[lcommon.Blake2b224]*localstatequery.PoolStateParams{},
		FState:   map[lcommon.Blake2b224]*localstatequery.PoolStateParams{},
		Retiring: map[lcommon.Blake2b224]uint64{},
		Deposits: map[lcommon.Blake2b224]uint64{},
	}
	res, err := poolQueryFromState(
		poolID, ps, nil, 1000, 129600, 62, 260, "preprod",
	)
	require.NoError(t, err)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, false, decoded["registered"])
	// An unregistered pool has null params and no locked deposit.
	params, ok := decoded["params"]
	require.True(t, ok, "params key must be present and null")
	require.Nil(t, params)
	require.Equal(t, float64(0), decoded["deposit"])
	_, ok = decoded["pending_params"]
	require.False(t, ok, "pending_params must be omitted")
	_, ok = decoded["retiring_epoch"]
	require.False(t, ok, "retiring_epoch must be omitted")
}

func TestPoolQueryFromStatePendingParams(t *testing.T) {
	poolID := testQueryPoolID()
	keyHash := lcommon.Blake2b224(poolID)
	registered := map[lcommon.Blake2b224]*localstatequery.PoolStateParams{
		keyHash: testQueryPoolParams(t),
	}
	// FState carries the pool: a parameter update is waiting to take effect.
	ps := &localstatequery.PoolStateResult{
		PState: registered,
		FState: map[lcommon.Blake2b224]*localstatequery.PoolStateParams{
			keyHash: testQueryPoolParams(t),
		},
	}
	res, err := poolQueryFromState(
		poolID, ps, nil, 1000, 129600, 62, 260, "preprod",
	)
	require.NoError(t, err)
	require.NotNil(t, res.PendingParams)
	require.Equal(t, "0.05", res.PendingParams.Margin)
	// FState without the pool: no pending params.
	ps.FState = map[lcommon.Blake2b224]*localstatequery.PoolStateParams{}
	res, err = poolQueryFromState(
		poolID, ps, nil, 1000, 129600, 62, 260, "preprod",
	)
	require.NoError(t, err)
	require.Nil(t, res.PendingParams)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	_, ok := decoded["pending_params"]
	require.False(t, ok)
}

func TestPoolQueryFromStateRetiring(t *testing.T) {
	poolID := testQueryPoolID()
	keyHash := lcommon.Blake2b224(poolID)
	ps := &localstatequery.PoolStateResult{
		PState: map[lcommon.Blake2b224]*localstatequery.PoolStateParams{
			keyHash: testQueryPoolParams(t),
		},
		Retiring: map[lcommon.Blake2b224]uint64{keyHash: 280},
	}
	res, err := poolQueryFromState(
		poolID, ps, nil, 1000, 129600, 62, 260, "preprod",
	)
	require.NoError(t, err)
	require.NotNil(t, res.RetiringEpoch)
	require.Equal(t, uint64(280), *res.RetiringEpoch)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, float64(280), decoded["retiring_epoch"])
}

func TestPoolQueryFromStateOpCertCounter(t *testing.T) {
	poolID := testQueryPoolID()
	keyHash := lcommon.Blake2b224(poolID)
	// A pool that has not forged has no on-chain counter: null, and the
	// first operational certificate uses counter 0.
	res, err := poolQueryFromState(
		poolID, nil, map[lcommon.Blake2b224]uint64{}, 1000, 129600, 62, 260,
		"preprod",
	)
	require.NoError(t, err)
	require.Nil(t, res.OpCert.OnChainCounter)
	require.Equal(t, uint64(0), res.OpCert.NextCounter)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	opcert, ok := decoded["opcert"].(map[string]any)
	require.True(t, ok)
	counter, ok := opcert["on_chain_counter"]
	require.True(t, ok, "on_chain_counter key must be present and null")
	require.Nil(t, counter)
	require.Equal(t, float64(0), opcert["next_counter"])
	// Counter 4 on chain: the next certificate uses 5.
	res, err = poolQueryFromState(
		poolID, nil, map[lcommon.Blake2b224]uint64{keyHash: 4}, 1000, 129600,
		62, 260, "preprod",
	)
	require.NoError(t, err)
	require.NotNil(t, res.OpCert.OnChainCounter)
	require.Equal(t, uint64(4), *res.OpCert.OnChainCounter)
	require.Equal(t, uint64(5), res.OpCert.NextCounter)
}

func TestCalculateKESPeriod(t *testing.T) {
	for _, tc := range []struct {
		slot     uint64
		perKES   int
		expected uint64
	}{
		{129600*5 + 7, 129600, 5},
		{129600 * 5, 129600, 5},
		{7, 129600, 0},
	} {
		period, err := calculateKESPeriod(tc.slot, tc.perKES)
		require.NoError(t, err)
		require.Equal(t, tc.expected, period)
	}
	// A nonpositive period is an error, not a plausible period 0.
	for _, perKES := range []int{0, -5} {
		_, err := calculateKESPeriod(100, perKES)
		require.Error(t, err, perKES)
	}
}

func TestPoolQueryFromStateRejectsZeroKESPeriod(t *testing.T) {
	_, err := poolQueryFromState(
		testQueryPoolID(), nil, nil, 100, 0, 62, 5, "preview",
	)
	require.Error(t, err)
}

func TestPoolParamsMarginRatio(t *testing.T) {
	params := testQueryPoolParams(t)
	params.Margin = &cbor.Rat{Rat: big.NewRat(1, 3)}
	res, err := poolParamsFromState(params, "preview")
	require.NoError(t, err)
	// The decimal is truncated; the ratio is exact.
	require.Equal(t, "0.33333333333333333333", res.Margin)
	require.Equal(t, "1/3", res.MarginRatio)
}

func TestPoolParamsNilMarginErrors(t *testing.T) {
	params := testQueryPoolParams(t)
	params.Margin = nil
	_, err := poolParamsFromState(params, "preview")
	require.ErrorContains(t, err, "margin")
}

func TestStakeCredentialFrom(t *testing.T) {
	hash := testQueryHash(0x42)
	for _, tc := range []struct {
		credType uint
		tag      uint64
	}{
		{lcommon.CredentialTypeAddrKeyHash, 0},
		{lcommon.CredentialTypeScriptHash, 1},
	} {
		got := stakeCredentialFrom(lcommon.Credential{
			CredType:   tc.credType,
			Credential: lcommon.CredentialHash(hash),
		})
		require.Equal(t, tc.tag, got.Tag)
		require.Equal(t, hash, got.Bytes)
	}
}

func TestParsePaymentAddress(t *testing.T) {
	cred := bytes.Repeat([]byte{0x33}, 28)
	enterprise := func(networkID uint8) string {
		addr, err := lcommon.NewAddressFromParts(
			lcommon.AddressTypeKeyNone, networkID, cred, nil,
		)
		require.NoError(t, err)
		return addr.String()
	}
	_, err := ParsePaymentAddress(enterprise(lcommon.AddressNetworkTestnet), "preview")
	require.NoError(t, err)
	_, err = ParsePaymentAddress(enterprise(lcommon.AddressNetworkMainnet), "preview")
	require.ErrorContains(t, err, "network")
	reward := testQueryRewardAddress(
		t, lcommon.AddressTypeNoneKey, lcommon.AddressNetworkTestnet, cred,
	)
	_, err = ParsePaymentAddress(reward.String(), "preview")
	require.ErrorContains(t, err, "stake")
}

func TestFormatMarginDecimal(t *testing.T) {
	for _, tc := range []struct {
		num, den int64
		expected string
	}{
		{1, 20, "0.05"},
		{0, 1, "0"},
		{3, 8, "0.375"},
		{1, 2, "0.5"},
		{999, 1000, "0.999"},
		{123450, 1000000, "0.12345"},
		{1, 1, "1"},
		// A non-terminating expansion is truncated at 20 fractional
		// digits, with no float rounding.
		{1, 3, "0.33333333333333333333"},
	} {
		require.Equal(
			t,
			tc.expected,
			formatMarginDecimal(big.NewRat(tc.num, tc.den)),
			"%d/%d",
			tc.num,
			tc.den,
		)
	}
}

func testQueryStakeCred() localstatequery.StakeCredential {
	return localstatequery.StakeCredential{Tag: 0, Bytes: testQueryHash(0x11)}
}

func TestStakeQueryFromUnregistered(t *testing.T) {
	cred := testQueryStakeCred()
	deposits := localstatequery.StakeDelegDepositsResult{}
	dr := &localstatequery.FilteredDelegationsAndRewardAccountsResult{}
	drepDelegs := localstatequery.FilteredVoteDelegateesResult{}
	res := stakeQueryFrom(cred, &deposits, dr, &drepDelegs)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	expected := `{
		"registered": false,
		"deposit": 0,
		"delegated_pool": null,
		"rewards": 0,
		"drep_delegation": null
	}`
	require.JSONEq(t, expected, string(data))
}

func TestStakeQueryFromRegisteredNotDelegated(t *testing.T) {
	cred := testQueryStakeCred()
	deposits := localstatequery.StakeDelegDepositsResult{cred: 2_000_000}
	dr := &localstatequery.FilteredDelegationsAndRewardAccountsResult{}
	drepDelegs := localstatequery.FilteredVoteDelegateesResult{}
	res := stakeQueryFrom(cred, &deposits, dr, &drepDelegs)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	expected := `{
		"registered": true,
		"deposit": 2000000,
		"delegated_pool": null,
		"rewards": 0,
		"drep_delegation": null
	}`
	require.JSONEq(t, expected, string(data))
}

func TestStakeQueryFromDelegatedWithRewards(t *testing.T) {
	cred := testQueryStakeCred()
	deposits := localstatequery.StakeDelegDepositsResult{cred: 2_000_000}
	dr := &localstatequery.FilteredDelegationsAndRewardAccountsResult{
		Delegations: map[localstatequery.StakeCredential]lcommon.Blake2b224{
			cred: testQueryHash(0x33),
		},
		Rewards: map[localstatequery.StakeCredential]uint64{cred: 1_234_567},
	}
	drepDelegs := localstatequery.FilteredVoteDelegateesResult{
		cred: lcommon.Drep{Type: lcommon.DrepTypeAbstain},
	}
	res := stakeQueryFrom(cred, &deposits, dr, &drepDelegs)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	expected := `{
		"registered": true,
		"deposit": 2000000,
		"delegated_pool": "pool1xvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxjllzk8",
		"rewards": 1234567,
		"drep_delegation": "drep_abstain"
	}`
	require.JSONEq(t, expected, string(data))
}

// Credential DReps are CIP-129 bech32, not bare hex.
func TestStakeQueryFromDRepCredential(t *testing.T) {
	cred := testQueryStakeCred()
	deposits := localstatequery.StakeDelegDepositsResult{cred: 2_000_000}
	dr := &localstatequery.FilteredDelegationsAndRewardAccountsResult{}
	for _, tc := range []struct {
		drep     lcommon.Drep
		expected string
	}{
		{
			lcommon.Drep{
				Type:       lcommon.DrepTypeAddrKeyHash,
				Credential: bytes.Repeat([]byte{0x44}, 28),
			},
			"drep1yfzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3q8yhklk",
		},
		{
			lcommon.Drep{
				Type:       lcommon.DrepTypeScriptHash,
				Credential: bytes.Repeat([]byte{0x55}, 28),
			},
			"drep1yd24242424242424242424242424242424242424242424gvs5tkq",
		},
		{
			lcommon.Drep{Type: lcommon.DrepTypeNoConfidence},
			"drep_no_confidence",
		},
	} {
		drepDelegs := localstatequery.FilteredVoteDelegateesResult{cred: tc.drep}
		res := stakeQueryFrom(cred, &deposits, dr, &drepDelegs)
		require.NotNil(t, res.DRepDelegation)
		require.Equal(t, tc.expected, *res.DRepDelegation)
	}
}

func TestParseRewardAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		network string
	}{
		{
			"testnet reward account on preprod",
			"stake_test1uqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygxtxu2s",
			"preprod",
		},
		{
			"testnet reward account on preview",
			"stake_test1uqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygxtxu2s",
			"preview",
		},
		{
			"mainnet reward account on mainnet",
			"stake1uyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygppv7wd",
			"mainnet",
		},
		{
			"script reward account on preprod",
			"stake_test17q3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs8a4sq7",
			"preprod",
		},
	} {
		addr, err := ParseRewardAddress(tc.address, tc.network)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.address, addr.String(), tc.name)
	}
	for _, tc := range []struct {
		name     string
		address  string
		network  string
		contains string
	}{
		{
			"payment address rejected",
			"addr_test1qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs5jexvf",
			"preprod",
			"reward",
		},
		{
			"mainnet payment address rejected",
			"addr1qyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshyyxqk",
			"mainnet",
			"reward",
		},
		{
			"mainnet address on preprod rejected",
			"stake1uyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygppv7wd",
			"preprod",
			"does not match",
		},
		{
			"testnet address on mainnet rejected",
			"stake_test1uqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygxtxu2s",
			"mainnet",
			"does not match",
		},
		{
			"garbage rejected",
			"notanaddress",
			"preprod",
			"invalid stake address",
		},
	} {
		_, err := ParseRewardAddress(tc.address, tc.network)
		require.ErrorContains(t, err, tc.contains, tc.name)
	}
}

func TestNetworkAddressId(t *testing.T) {
	for _, tc := range []struct {
		network  string
		expected uint8
	}{
		{"preprod", lcommon.AddressNetworkTestnet},
		{"preview", lcommon.AddressNetworkTestnet},
		{"mainnet", lcommon.AddressNetworkMainnet},
		{"764824073", lcommon.AddressNetworkMainnet},
		{"42", lcommon.AddressNetworkTestnet},
	} {
		id, err := networkAddressId(tc.network)
		require.NoError(t, err, tc.network)
		require.Equal(t, tc.expected, id, tc.network)
	}
	for _, network := range []string{"", "notanetwork"} {
		_, err := networkAddressId(network)
		require.Error(t, err, "network %q", network)
	}
}

func testQueryUtxo(
	txID byte,
	idx int,
	lovelace uint64,
	assets *lcommon.MultiAsset[lcommon.MultiAssetTypeOutput],
) (localstatequery.UtxoId, babbage.BabbageTransactionOutput) {
	id := localstatequery.UtxoId{
		Hash: lcommon.Blake2b256(bytes.Repeat([]byte{txID}, 32)),
		Idx:  idx,
	}
	out := babbage.BabbageTransactionOutput{
		OutputAmount: mary.MaryTransactionOutputValue{
			Amount: lovelace,
			Assets: assets,
		},
	}
	return id, out
}

func TestUTxOQueryFromSortsByTxIDThenIndex(t *testing.T) {
	res := &localstatequery.UTxOsResult{
		Results: map[localstatequery.UtxoId]babbage.BabbageTransactionOutput{},
	}
	for _, spec := range []struct {
		txID byte
		idx  int
	}{
		{0xbb, 0},
		{0xaa, 1},
		{0xaa, 0},
	} {
		id, out := testQueryUtxo(spec.txID, spec.idx, 1_000_000, nil)
		res.Results[id] = out
	}
	got, err := utxoQueryFrom(res)
	require.NoError(t, err)
	require.Len(t, got, 3)
	wantOrder := []struct {
		txID string
		idx  uint32
	}{
		{testQueryHex(0xaa, 32), 0},
		{testQueryHex(0xaa, 32), 1},
		{testQueryHex(0xbb, 32), 0},
	}
	for i, want := range wantOrder {
		require.Equal(t, want.txID, got[i].TxID)
		require.Equal(t, want.idx, got[i].Index)
	}
}

func TestUTxOQueryFromAssets(t *testing.T) {
	policy := lcommon.Blake2b224(bytes.Repeat([]byte{0x99}, 28))
	assets := lcommon.NewMultiAsset(
		map[lcommon.Blake2b224]map[cbor.ByteString]*big.Int{
			policy: {
				cbor.NewByteString([]byte("tokenA")): big.NewInt(100),
				cbor.NewByteString([]byte("tokenB")): big.NewInt(200),
			},
		},
	)
	res := &localstatequery.UTxOsResult{
		Results: map[localstatequery.UtxoId]babbage.BabbageTransactionOutput{},
	}
	id, out := testQueryUtxo(0xaa, 0, 5_000_000, &assets)
	res.Results[id] = out
	got, err := utxoQueryFrom(res)
	require.NoError(t, err)
	require.Len(t, got, 1)
	data, err := json.Marshal(got[0])
	require.NoError(t, err)
	expected := `{
		"tx_id": "` + testQueryHex(0xaa, 32) + `",
		"index": 0,
		"lovelace": 5000000,
		"assets": {
			"` + testQueryHex(0x99, 28) + `": {
				"746f6b656e41": "100",
				"746f6b656e42": "200"
			}
		}
	}`
	require.JSONEq(t, expected, string(data))
}

func TestUTxOQueryFromRejectsNegativeIndex(t *testing.T) {
	res := &localstatequery.UTxOsResult{
		Results: map[localstatequery.UtxoId]babbage.BabbageTransactionOutput{},
	}
	id, out := testQueryUtxo(0xaa, -1, 1_000_000, nil)
	res.Results[id] = out
	_, err := utxoQueryFrom(res)
	require.ErrorContains(t, err, "out of range")
}

func TestTipQueryFrom(t *testing.T) {
	res, err := tipQueryFrom(6, 260, 4_567_890, 129600*5+7, 129600)
	require.NoError(t, err)
	data, err := json.Marshal(res)
	require.NoError(t, err)
	expected := `{
		"era": "Conway",
		"epoch": 260,
		"slot": 648007,
		"block_number": 4567890,
		"kes_period": 5
	}`
	require.JSONEq(t, expected, string(data))
	res, err = tipQueryFrom(0, 1, 2, 3, 129600)
	require.NoError(t, err)
	require.Equal(t, "Byron", res.Era)
}

func TestTipQueryFromUnknownEra(t *testing.T) {
	_, err := tipQueryFrom(99, 260, 4_567_890, 648007, 129600)
	require.ErrorContains(t, err, "unknown era")
	_, err = tipQueryFrom(-1, 260, 4_567_890, 648007, 129600)
	require.ErrorContains(t, err, "unknown era")
}
