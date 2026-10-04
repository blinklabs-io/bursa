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
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/sops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keyDestinationCase struct {
	name   string
	run    func(skey, vkey string) error
	prefix string
	// hasVKey is false for commands with no verification key output.
	hasVKey bool
}

func keyDestinationCases() []keyDestinationCase {
	m := testKeyMnemonic
	return []keyDestinationCase{
		{"root", func(s, _ string) error { return RunKeyRoot(m, "", "", s) }, "root_xsk", false},
		{"account", func(s, _ string) error { return RunKeyAccount(m, "", "", s, 0) }, "acct_xsk", false},
		{"payment", func(s, v string) error { return RunKeyPayment(m, "", "", s, v, 0, 0) }, "addr_xsk", true},
		{"stake", func(s, v string) error { return RunKeyStake(m, "", "", s, v, 0, 0) }, "stake_xsk", true},
		{"policy", func(s, v string) error { return RunKeyPolicy(m, "", "", s, v, 0) }, "policy_xsk", true},
		{"pool-cold", func(s, v string) error { return RunKeyPoolCold(m, "", "", s, v, 0) }, "pool_xsk", true},
		{"calidus", func(s, v string) error { return RunKeyCalidus(m, "", "", s, v, 0, 0) }, "calidus_xsk", true},
		{"drep", func(s, v string) error { return RunKeyDRep(m, "", "", s, v, 0, 0) }, "drep_xsk", true},
		{"committee-cold", func(s, v string) error { return RunKeyCommitteeCold(m, "", "", s, v, 0, 0) }, "cc_cold_xsk", true},
		{"committee-hot", func(s, v string) error { return RunKeyCommitteeHot(m, "", "", s, v, 0, 0) }, "cc_hot_xsk", true},
		{"vrf", func(s, v string) error { return RunKeyVRF(m, "", "", s, v, 0) }, "vrf_skey: vrf_sk", true},
		{"kes", func(s, v string) error { return RunKeyKES(m, "", "", s, v, 0) }, "kes_skey: kes_sk", true},
	}
}

// Not t.Parallel: captureStdout swaps the process-wide os.Stdout.
func TestKeyDerivationRequiresExplicitDestination(t *testing.T) {
	for _, tc := range keyDestinationCases() {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() { err = tc.run("", "") })
			require.Error(t, err)
			assert.Contains(t, err.Error(), "destination")
			assert.Empty(t, out, "no secret may be printed without a destination")
		})
	}
}

// Not t.Parallel: captureStdout swaps the process-wide os.Stdout.
func TestKeyDerivationDashWritesToStdout(t *testing.T) {
	for _, tc := range keyDestinationCases() {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() { err = tc.run("-", "") })
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(out, tc.prefix), "got %q", out)
		})
	}
}

// Not t.Parallel: captureStdout swaps the process-wide os.Stdout.
func TestKeyDerivationVerificationOnlyNeedsNoSecretDestination(t *testing.T) {
	for _, tc := range keyDestinationCases() {
		if !tc.hasVKey {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			vkey := filepath.Join(t.TempDir(), "out.vkey")
			var err error
			out := captureStdout(t, func() { err = tc.run("", vkey) })
			require.NoError(t, err)
			assert.Empty(t, out)
		})
	}
}

// Not t.Parallel: captureStdout swaps the process-wide os.Stdout.
func TestKeyDerivationDashCannotCombineWithVerificationFile(t *testing.T) {
	err := RunKeyPayment(
		testKeyMnemonic, "", "", "-", filepath.Join(t.TempDir(), "p.vkey"), 0, 0,
	)
	require.Error(t, err)
}

// Not t.Parallel: captureStdout swaps the process-wide os.Stdout.
func TestRunKeyDecryptRequiresExplicitDestination(t *testing.T) {
	plaintext := []byte(`{"type":"PaymentSigningKeyShelley_ed25519","cborHex":"5820deadbeef"}`)
	enc, err := sops.EncryptWithPassphrase(plaintext, "right")
	require.NoError(t, err)
	in := filepath.Join(t.TempDir(), "k.enc")
	require.NoError(t, writeSecretFileAtomic(in, enc))

	out := captureStdout(t, func() { err = RunKeyDecrypt(in, "", "right") })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination")
	assert.Empty(t, out)

	out = captureStdout(t, func() { err = RunKeyDecrypt(in, "-", "right") })
	require.NoError(t, err)
	assert.Equal(t, string(plaintext), out)
}
