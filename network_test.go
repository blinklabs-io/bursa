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

package bursa

import (
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/stretchr/testify/require"
)

func TestAddressNetworkNamesAndMagic(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)
	require.NoError(t, err)
	accountKey, err := GetAccountKey(rootKey, 0)
	require.NoError(t, err)
	stakeKey, err := GetStakeKey(accountKey, 0)
	require.NoError(t, err)
	stakeVKey, err := GetStakeVKey(stakeKey)
	require.NoError(t, err)
	script, err := NewScriptSig(make([]byte, 28))
	require.NoError(t, err)

	tests := []struct {
		network string
		mainnet bool
	}{
		{network: "mainnet", mainnet: true},
		{network: "764824073", mainnet: true},
		{network: "prime-mainnet", mainnet: true},
		{network: "testnet"},
		{network: "preprod"},
		{network: "1"},
		{network: "preview"},
		{network: "2"},
		{network: "sanchonet"},
		{network: "4"},
		{network: "dijkstra"},
		{network: "6"},
		{network: "musashi"},
		{network: "164"},
		{network: "prime-testnet"},
		{network: "3311"},
		{network: "devnet"},
		{network: "42"},
		{network: "1097911063"},
	}
	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			wantNetworkID := uint(lcommon.AddressNetworkTestnet)
			if tt.mainnet {
				wantNetworkID = lcommon.AddressNetworkMainnet
			}

			addr, err := GetAddress(accountKey, tt.network, 0)
			require.NoError(t, err)
			require.Equal(t, wantNetworkID, addr.NetworkId())

			rewardAddr, err := GetRewardAddress(stakeVKey, tt.network)
			require.NoError(t, err)
			require.Equal(t, wantNetworkID, rewardAddr.NetworkId())

			scriptAddr, err := GetScriptAddress(script, tt.network)
			require.NoError(t, err)
			parsedScriptAddr, err := lcommon.NewAddress(scriptAddr)
			require.NoError(t, err)
			require.Equal(t, wantNetworkID, parsedScriptAddr.NetworkId())

			wallet, err := NewWallet(
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
				WithNetwork(tt.network),
			)
			require.NoError(t, err)
			walletAddr, err := lcommon.NewAddress(wallet.PaymentAddress)
			require.NoError(t, err)
			require.Equal(t, wantNetworkID, walletAddr.NetworkId())
		})
	}
}

func TestAddressNetworkRejectsInvalidMagic(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)
	require.NoError(t, err)
	accountKey, err := GetAccountKey(rootKey, 0)
	require.NoError(t, err)

	for _, network := range []string{"-1", "4294967296"} {
		t.Run(network, func(t *testing.T) {
			_, err := GetAddress(accountKey, network, 0)
			require.ErrorIs(t, err, ErrInvalidNetwork)
		})
	}
}
