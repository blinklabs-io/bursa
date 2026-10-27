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
	"strings"
	"testing"

	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/stretchr/testify/require"
)

func TestCLICommandsAcceptCommonNetworks(t *testing.T) {
	const (
		paymentVKey = "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"
		mnemonic    = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		keyHash     = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
	)
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
			var buildErr error
			buildOutput := captureStdout(t, func() {
				buildErr = RunAddressBuild(paymentVKey, "", tt.network, "enterprise")
			})
			require.NoError(t, buildErr)

			var enterpriseErr error
			enterpriseOutput := captureStdout(t, func() {
				enterpriseErr = RunAddressEnterprise(paymentVKey, "", tt.network)
			})
			require.NoError(t, enterpriseErr)
			require.Equal(t, buildOutput, enterpriseOutput)

			addr, err := lcommon.NewAddress(strings.TrimSpace(buildOutput))
			require.NoError(t, err)
			wantNetworkID := uint(lcommon.AddressNetworkTestnet)
			if tt.mainnet {
				wantNetworkID = lcommon.AddressNetworkMainnet
			}
			require.Equal(t, wantNetworkID, addr.NetworkId())

			var scriptErr error
			captureStdout(t, func() {
				scriptErr = RunScriptCreate(
					1, []string{keyHash}, "", tt.network,
					false, false, 0, 0,
				)
			})
			require.NoError(t, scriptErr)

			var listErr error
			captureStdout(t, func() {
				listErr = RunAddressList(mnemonic, "", "", tt.network, 0, 0, 1)
			})
			require.NoError(t, listErr)
		})
	}
}
