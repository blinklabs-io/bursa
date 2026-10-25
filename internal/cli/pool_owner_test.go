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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptStakeAddr is a mainnet stake address with a script credential,
// built by cardano-cli 11.0.0.0 `stake-address build --stake-script-file`.
const scriptStakeAddr = "stake1798a7qlrt2mz3n0c5lk3hsppx4h9jg4t8tkfgqe7w7rru6szzxrqw"

func poolRegistrationKeyFiles(t *testing.T, dir string) (string, string) {
	t.Helper()
	coldVkey := createTestVkeyFile(
		t, dir, "cold.vkey",
		"StakePoolVerificationKey_ed25519",
		"Stake Pool Operator Verification Key",
		testColdVKeyCborHex,
	)
	vrfVkey := createTestVkeyFile(
		t, dir, "vrf.vkey",
		"VrfVerificationKey_PraosVRF",
		"VRF Verification Key",
		testVRFVKeyCborHex,
	)
	return coldVkey, vrfVkey
}

func TestRunCertPoolRegistration_RejectsNonStakeOwnerKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		keyType string
		raw     bool
	}{
		{name: "cold key", keyType: "StakePoolVerificationKey_ed25519"},
		{name: "payment key", keyType: "PaymentVerificationKeyShelley_ed25519"},
		{name: "raw hex without envelope", raw: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			coldVkey, vrfVkey := poolRegistrationKeyFiles(t, dir)
			var owner string
			if tc.raw {
				owner = filepath.Join(dir, "owner.vkey")
				require.NoError(t, os.WriteFile(
					owner, []byte(goldenStakeVKeyCborHex[4:]), 0o600,
				))
			} else {
				owner = createTestVkeyFile(
					t, dir, "owner.vkey", tc.keyType, "",
					goldenStakeVKeyCborHex,
				)
			}
			err := RunCertPoolRegistration(
				coldVkey, vrfVkey, goldenStakeAddr,
				filepath.Join(dir, "pool-reg.cert"),
				1_000_000_000, 340_000_000, 0.03, "", "",
				[]string{owner}, PoolRelayFlags{},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "owner")
		})
	}
}

func TestRunCertPoolRegistration_ScriptRewardAccountNeedsOwner(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	coldVkey, vrfVkey := poolRegistrationKeyFiles(t, dir)
	err := RunCertPoolRegistration(
		coldVkey, vrfVkey, scriptStakeAddr,
		filepath.Join(dir, "pool-reg.cert"),
		1_000_000_000, 340_000_000, 0.03, "", "",
		nil, PoolRelayFlags{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--owner-stake-vkey")
}
