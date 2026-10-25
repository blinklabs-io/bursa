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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package cli

import (
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cardano-cli reads a vrf_sk bech32 key as the seed followed by the public
// key, the same layout as the VRF signing key file.
func TestRunKeyVRFBech32SigningKeyIsSeedAndPublicKey(t *testing.T) {
	output := captureStdout(t, func() {
		require.NoError(t, RunKeyVRF(testKeyMnemonic, "", "", "-", "", 0))
	})

	decoded := map[string][]byte{}
	for line := range strings.SplitSeq(output, "\n") {
		label, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		hrp, data, err := bech32.DecodeNoLimit(strings.TrimSpace(value))
		require.NoError(t, err, label)
		raw, err := bech32.ConvertBits(data, 5, 8, false)
		require.NoError(t, err, label)
		decoded[hrp] = raw
	}

	root, err := bursa.GetRootKeyFromMnemonic(testKeyMnemonic, "")
	require.NoError(t, err)
	seed, err := bursa.GetVRFSeed(root, 0)
	require.NoError(t, err)
	pub, _, err := bursa.GetVRFKeyPair(seed)
	require.NoError(t, err)

	require.Contains(t, decoded, "vrf_sk")
	require.Contains(t, decoded, "vrf_vk")
	assert.Equal(t, pub, decoded["vrf_vk"])
	assert.Equal(t, append(append([]byte(nil), seed...), pub...), decoded["vrf_sk"])
}
