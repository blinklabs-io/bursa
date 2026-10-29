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
	"testing"

	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/stretchr/testify/require"
)

func TestNetworkMagic(t *testing.T) {
	for _, tc := range []struct {
		network string
		magic   uint32
	}{
		{"preprod", 1},
		{"preview", 2},
		{"mainnet", 764824073},
		{"sanchonet", 4},
		{"42", 42},
	} {
		got, err := networkMagic(tc.network)
		require.NoError(t, err, tc.network)
		require.Equal(t, tc.magic, got, tc.network)
	}
	for _, network := range []string{"", "notanetwork"} {
		_, err := networkMagic(network)
		require.Error(t, err, "network %q", network)
	}
}

func TestConwayParams(t *testing.T) {
	pp := &conway.ConwayProtocolParameters{}
	pp.MinFeeA = 44
	pp.MinFeeB = 155381
	pp.KeyDeposit = 2_000_000
	pp.PoolDeposit = 500_000_000
	pp.MaxTxSize = 16384
	pp.AdaPerUtxoByte = 4310
	fee, extra, err := conwayParams(pp)
	require.NoError(t, err)
	require.Equal(t, uint64(44), fee.TxFeePerByte)
	require.Equal(t, uint64(155381), fee.TxFeeFixed)
	require.Equal(t, ProtocolParametersExtra{
		MinFeeA:          44,
		MinFeeB:          155381,
		KeyDeposit:       2_000_000,
		PoolDeposit:      500_000_000,
		MaxTxSize:        16384,
		CoinsPerUTxOByte: 4310,
	}, *extra)
}

func TestConwayParamsRejectsOtherEras(t *testing.T) {
	_, _, err := conwayParams(&babbage.BabbageProtocolParameters{})
	require.ErrorContains(t, err, "not in the Conway era")
}
