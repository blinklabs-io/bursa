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

package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa/internal/txbuilder"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/stretchr/testify/require"
)

const (
	testQueryMissingSocket = "missing.socket"
	testQueryPoolBech32    = "pool1xvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxjllzk8"
	testQueryPoolHex       = "33333333333333333333333333333333333333333333333333333333"
	testQueryStakeTestnet  = "stake_test1uqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygxtxu2s"
	testQueryStakeMainnet  = "stake1uyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygppv7wd"
	testQueryPaymentAddr   = "addr_test1qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs5jexvf"
)

func TestRunQueryPoolRequiresSocketPath(t *testing.T) {
	err := RunQueryPool("", "preprod", testQueryPoolBech32, "", 5)
	require.ErrorContains(t, err, "--socket-path")
}

func TestRunQueryPoolRequiresNetwork(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryPool(socket, "", testQueryPoolBech32, "", 5)
	require.ErrorContains(t, err, "--network")
}

func TestRunQueryStakeAddressRequiresSocketPath(t *testing.T) {
	err := RunQueryStakeAddress("", "preprod", testQueryStakeTestnet, "", 5)
	require.ErrorContains(t, err, "--socket-path")
}

func TestRunQueryStakeAddressRequiresNetwork(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryStakeAddress(socket, "", testQueryStakeTestnet, "", 5)
	require.ErrorContains(t, err, "--network")
}

func TestRunQueryUtxoRequiresSocketPath(t *testing.T) {
	err := RunQueryUtxo("", "preprod", testQueryPaymentAddr, "", 5)
	require.ErrorContains(t, err, "--socket-path")
}

func TestRunQueryUtxoRequiresNetwork(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryUtxo(socket, "", testQueryPaymentAddr, "", 5)
	require.ErrorContains(t, err, "--network")
}

func TestRunQueryTipRequiresSocketPath(t *testing.T) {
	err := RunQueryTip("", "preprod", "", 5)
	require.ErrorContains(t, err, "--socket-path")
}

func TestRunQueryTipRequiresNetwork(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryTip(socket, "", "", 5)
	require.ErrorContains(t, err, "--network")
}

// A bad pool id is reported before the node is dialed: the socket path does
// not exist, so a dial would fail with a different error.
func TestRunQueryPoolValidatesPoolIDBeforeDialing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	for _, poolID := range []string{"notapool", "deadbeef", "pool1bogus"} {
		err := RunQueryPool(socket, "preprod", poolID, "", 5)
		require.ErrorContains(t, err, "--pool-id", "pool id %q", poolID)
	}
}

// A valid pool id reaches the dial, so the error is about the missing
// socket, not the flag.
func TestRunQueryPoolAcceptsPoolIDBeforeDialing(t *testing.T) {
	for _, poolID := range []string{testQueryPoolBech32, testQueryPoolHex} {
		socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
		err := RunQueryPool(socket, "preprod", poolID, "", 5)
		require.Error(t, err, "pool id %q", poolID)
		require.NotContains(t, err.Error(), "--pool-id", "pool id %q", poolID)
	}
}

// A bad address is reported before the node is dialed.
func TestRunQueryStakeAddressValidatesAddressBeforeDialing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryStakeAddress(socket, "preprod", "notanaddress", "", 5)
	require.ErrorContains(t, err, "--address")
}

// A payment address is not a stake address: its stake part would answer the
// wrong query.
func TestRunQueryStakeAddressRejectsPaymentAddress(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryStakeAddress(socket, "preprod", testQueryPaymentAddr, "", 5)
	require.ErrorContains(t, err, "--address")
	require.ErrorContains(t, err, "reward")
}

// The stake address network must match --network.
func TestRunQueryStakeAddressRejectsWrongNetwork(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryStakeAddress(socket, "preprod", testQueryStakeMainnet, "", 5)
	require.ErrorContains(t, err, "does not match")
	err = RunQueryStakeAddress(socket, "mainnet", testQueryStakeTestnet, "", 5)
	require.ErrorContains(t, err, "does not match")
}

// A valid stake address reaches the dial.
func TestRunQueryStakeAddressAcceptsAddressBeforeDialing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryStakeAddress(socket, "preprod", testQueryStakeTestnet, "", 5)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "--address")
	require.NotContains(t, err.Error(), "does not match")
}

// A bad address is reported before the node is dialed.
func TestRunQueryUtxoValidatesAddressBeforeDialing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryUtxo(socket, "preprod", "notanaddress", "", 5)
	require.ErrorContains(t, err, "--address")
}

// A valid address reaches the dial.
func TestRunQueryUtxoAcceptsAddressBeforeDialing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryUtxo(socket, "preprod", testQueryPaymentAddr, "", 5)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "--address")
}

func TestRunQueryRejectsNonpositiveTimeout(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	for _, timeout := range []int64{0, -5} {
		require.ErrorContains(t, RunQueryTip(socket, "preprod", "", timeout), "--timeout")
		require.ErrorContains(
			t,
			RunQueryPool(socket, "preprod", testQueryPoolHex, "", timeout),
			"--timeout",
		)
		require.ErrorContains(
			t,
			RunQueryStakeAddress(socket, "preprod", testQueryStakeTestnet, "", timeout),
			"--timeout",
		)
		require.ErrorContains(
			t,
			RunQueryUtxo(socket, "preprod", testQueryPaymentAddr, "", timeout),
			"--timeout",
		)
	}
}

func TestRunQueryUtxoRejectsWrongNetworkBeforeDialing(t *testing.T) {
	socket := filepath.Join(t.TempDir(), testQueryMissingSocket)
	err := RunQueryUtxo(socket, "mainnet", testQueryPaymentAddr, "", 5)
	require.ErrorContains(t, err, "--address")
	err = RunQueryUtxo(socket, "preprod", testQueryStakeTestnet, "", 5)
	require.ErrorContains(t, err, "--address")
}

func TestRunQueryTipWritesOutFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "tip.json")
	var gotNetwork string
	runner := func(
		ctx context.Context, socketPath, network string,
	) (*txbuilder.TipQueryResult, error) {
		_, hasDeadline := ctx.Deadline()
		require.True(t, hasDeadline)
		gotNetwork = network
		return &txbuilder.TipQueryResult{Era: "Conway", Epoch: 7, Slot: 42}, nil
	}
	require.NoError(t, runQueryTip("node.socket", "preview", out, 5, runner))
	require.Equal(t, "preview", gotNetwork)
	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, "Conway", got["era"])
	require.InDelta(t, 42, got["slot"], 0)
}

func TestRunQueryPoolPassesParsedPoolID(t *testing.T) {
	var got lcommon.PoolId
	runner := func(
		_ context.Context, _, _ string, poolID lcommon.PoolId,
	) (*txbuilder.PoolQueryResult, error) {
		got = poolID
		return &txbuilder.PoolQueryResult{}, nil
	}
	out := filepath.Join(t.TempDir(), "pool.json")
	require.NoError(t, runQueryPool("node.socket", "preview", testQueryPoolBech32, out, 5, runner))
	require.Equal(t, testQueryPoolHex, hex.EncodeToString(got[:]))
}

func TestRunQueryReportsRunnerError(t *testing.T) {
	runner := func(
		context.Context, string, string,
	) (*txbuilder.TipQueryResult, error) {
		return nil, errors.New("acquire failed")
	}
	err := runQueryTip("node.socket", "preview", "", 5, runner)
	require.ErrorContains(t, err, "acquire failed")
}
