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
	"path/filepath"
	"testing"

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
