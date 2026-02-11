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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeyMnemonic is a well-known CIP-1852 test vector mnemonic.
// DO NOT USE FOR REAL FUNDS.
const testKeyMnemonic = "abandon abandon abandon abandon " +
	"abandon abandon abandon abandon " +
	"abandon abandon abandon about"

func TestRunKeyRoot_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyRoot(testKeyMnemonic, "", "", "")
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "root_xsk"),
		"root key should start with root_xsk prefix",
	)
}

func TestRunKeyRoot_MissingMnemonic(t *testing.T) {
	err := RunKeyRoot("", "", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no mnemonic provided")
}

func TestRunKeyRoot_SigningKeyFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-root-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	skeyFile := filepath.Join(tempDir, "root.skey")
	err = RunKeyRoot(testKeyMnemonic, "", "", skeyFile)
	require.NoError(t, err)

	data, err := os.ReadFile(skeyFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "cborHex")
}

func TestRunKeyAccount_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyAccount(
			testKeyMnemonic, "", "", "", 0,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "acct_xsk"),
		"account key should start with acct_xsk prefix",
	)
}

func TestRunKeyAccount_MissingMnemonic(t *testing.T) {
	err := RunKeyAccount("", "", "", "", 0)
	assert.Error(t, err)
}

func TestRunKeyAccount_SigningKeyFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-acct-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	skeyFile := filepath.Join(tempDir, "acct.skey")
	err = RunKeyAccount(
		testKeyMnemonic, "", "", skeyFile, 0,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(skeyFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "cborHex")
}

func TestRunKeyPayment_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyPayment(
			testKeyMnemonic, "", "", "", "", 0, 0,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "addr_xsk"),
		"payment key should start with addr_xsk prefix",
	)
}

func TestRunKeyPayment_MissingMnemonic(t *testing.T) {
	err := RunKeyPayment("", "", "", "", "", 0, 0)
	assert.Error(t, err)
}

func TestRunKeyStake_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyStake(
			testKeyMnemonic, "", "", "", "", 0, 0,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "stake_xsk"),
		"stake key should start with stake_xsk prefix",
	)
}

func TestRunKeyStake_MissingMnemonic(t *testing.T) {
	err := RunKeyStake("", "", "", "", "", 0, 0)
	assert.Error(t, err)
}

func TestRunKeyPolicy_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyPolicy(
			testKeyMnemonic, "", "", "", "", 0,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "policy_xsk"),
		"policy key should start with policy_xsk prefix",
	)
}

func TestRunKeyPolicy_MissingMnemonic(t *testing.T) {
	err := RunKeyPolicy("", "", "", "", "", 0)
	assert.Error(t, err)
}

func TestRunKeyPoolCold_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyPoolCold(
			testKeyMnemonic, "", "", "", "", 0,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "pool_xsk"),
		"pool cold key should start with pool_xsk prefix",
	)
}

func TestRunKeyPoolCold_MissingMnemonic(t *testing.T) {
	err := RunKeyPoolCold("", "", "", "", "", 0)
	assert.Error(t, err)
}

func TestRunKeyDRep_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyDRep(
			testKeyMnemonic, "", "", "", "", 0, 0,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "drep_xsk"),
		"drep key should start with drep_xsk prefix",
	)
}

func TestRunKeyDRep_MissingMnemonic(t *testing.T) {
	err := RunKeyDRep("", "", "", "", "", 0, 0)
	assert.Error(t, err)
}

func TestRunKeyCommitteeCold_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyCommitteeCold(
			testKeyMnemonic, "", "", "", "", 0, 0,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "cc_cold_xsk"),
		"committee cold key should have cc_cold_xsk prefix",
	)
}

func TestRunKeyCommitteeCold_MissingMnemonic(t *testing.T) {
	err := RunKeyCommitteeCold("", "", "", "", "", 0, 0)
	assert.Error(t, err)
}

func TestRunKeyCommitteeHot_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyCommitteeHot(
			testKeyMnemonic, "", "", "", "", 0, 0,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "cc_hot_xsk"),
		"committee hot key should have cc_hot_xsk prefix",
	)
}

func TestRunKeyCommitteeHot_MissingMnemonic(t *testing.T) {
	err := RunKeyCommitteeHot("", "", "", "", "", 0, 0)
	assert.Error(t, err)
}

func TestRunKeyVRF_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyVRF(
			testKeyMnemonic, "", "", "", "", 0,
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "vrf_skey:")
	assert.Contains(t, output, "vrf_vkey:")
	// Extract the vrf_skey value
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "vrf_skey:") {
			key := strings.TrimSpace(
				strings.TrimPrefix(line, "vrf_skey:"),
			)
			assert.True(
				t,
				strings.HasPrefix(key, "vrf_sk"),
				"VRF signing key should have vrf_sk prefix",
			)
		}
		if strings.HasPrefix(line, "vrf_vkey:") {
			key := strings.TrimSpace(
				strings.TrimPrefix(line, "vrf_vkey:"),
			)
			assert.True(
				t,
				strings.HasPrefix(key, "vrf_vk"),
				"VRF verification key should have vrf_vk prefix",
			)
		}
	}
}

func TestRunKeyVRF_MissingMnemonic(t *testing.T) {
	err := RunKeyVRF("", "", "", "", "", 0)
	assert.Error(t, err)
}

func TestRunKeyKES_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyKES(
			testKeyMnemonic, "", "", "", "", 0,
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "kes_skey:")
	assert.Contains(t, output, "kes_vkey:")
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "kes_skey:") {
			key := strings.TrimSpace(
				strings.TrimPrefix(line, "kes_skey:"),
			)
			assert.True(
				t,
				strings.HasPrefix(key, "kes_sk"),
				"KES signing key should have kes_sk prefix",
			)
		}
		if strings.HasPrefix(line, "kes_vkey:") {
			key := strings.TrimSpace(
				strings.TrimPrefix(line, "kes_vkey:"),
			)
			assert.True(
				t,
				strings.HasPrefix(key, "kes_vk"),
				"KES verification key should have kes_vk prefix",
			)
		}
	}
}

func TestRunKeyKES_MissingMnemonic(t *testing.T) {
	err := RunKeyKES("", "", "", "", "", 0)
	assert.Error(t, err)
}

func TestRunKeyPayment_NonZeroIndex(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyPayment(
			testKeyMnemonic, "", "", "", "", 1, 2,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "addr_xsk"),
		"payment key with non-zero index should work",
	)
}

func TestRunKeyStake_NonZeroIndex(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyStake(
			testKeyMnemonic, "", "", "", "", 1, 1,
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "stake_xsk"),
		"stake key with non-zero index should work",
	)
}

func TestRunKeyRoot_WithPassword(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyRoot(
			testKeyMnemonic, "", "testpassword", "",
		)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "root_xsk"),
		"root key with password should work",
	)
}

func TestRunKeyPayment_DifferentIndicesProduceDifferentKeys(
	t *testing.T,
) {
	output0 := captureStdout(t, func() {
		err := RunKeyPayment(
			testKeyMnemonic, "", "", "", "", 0, 0,
		)
		require.NoError(t, err)
	})
	output1 := captureStdout(t, func() {
		err := RunKeyPayment(
			testKeyMnemonic, "", "", "", "", 0, 1,
		)
		require.NoError(t, err)
	})
	assert.NotEqual(
		t, output0, output1,
		"different indices should produce different keys",
	)
}

func TestResolveMnemonic_DirectMnemonic(t *testing.T) {
	result, err := resolveMnemonic(testKeyMnemonic, "")
	require.NoError(t, err)
	assert.Equal(t, testKeyMnemonic, result)
}

func TestResolveMnemonic_EnvVariable(t *testing.T) {
	t.Setenv("MNEMONIC", testKeyMnemonic)
	result, err := resolveMnemonic("", "")
	require.NoError(t, err)
	assert.Equal(t, testKeyMnemonic, result)
}

func TestResolveMnemonic_File(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-mnemonic-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mnemonicFile := filepath.Join(tempDir, "seed.txt")
	err = os.WriteFile(
		mnemonicFile,
		[]byte(testKeyMnemonic+"\n"),
		0o600,
	)
	require.NoError(t, err)

	result, err := resolveMnemonic("", mnemonicFile)
	require.NoError(t, err)
	assert.Equal(t, testKeyMnemonic, result)
}

func TestResolveMnemonic_NonexistentFile(t *testing.T) {
	_, err := resolveMnemonic("", "/nonexistent/path/seed.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read mnemonic file")
}

func TestResolveMnemonic_NoSource(t *testing.T) {
	// Ensure MNEMONIC env var is not set
	t.Setenv("MNEMONIC", "")
	_, err := resolveMnemonic("", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no mnemonic provided")
}

func TestResolveMnemonic_TrimsWhitespace(t *testing.T) {
	result, err := resolveMnemonic(
		"  "+testKeyMnemonic+"  \n",
		"",
	)
	require.NoError(t, err)
	assert.Equal(t, testKeyMnemonic, result)
}

func TestEncodeExtendedPrivateKey(t *testing.T) {
	// Create a 64-byte test key
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}

	encoded, err := encodeExtendedPrivateKey(key, "test_xsk")
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "test_xsk"),
		"encoded key should have the correct prefix",
	)
}

func TestEncodeAccountKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodeAccountKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "acct_xsk"),
	)
}

func TestEncodePaymentKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodePaymentKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "addr_xsk"),
	)
}

func TestEncodeStakeKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodeStakeKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "stake_xsk"),
	)
}

func TestEncodePolicyKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodePolicyKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "policy_xsk"),
	)
}

func TestEncodePoolColdKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodePoolColdKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "pool_xsk"),
	)
}

func TestEncodeDRepKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodeDRepKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "drep_xsk"),
	)
}

func TestEncodeCommitteeColdKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodeCommitteeColdKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "cc_cold_xsk"),
	)
}

func TestEncodeCommitteeHotKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodeCommitteeHotKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "cc_hot_xsk"),
	)
}

func TestEncodeVRFSigningKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodeVRFSigningKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "vrf_sk"),
	)
}

func TestEncodeVRFVerificationKey(t *testing.T) {
	key := make([]byte, 32)
	encoded, err := encodeVRFVerificationKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "vrf_vk"),
	)
}

func TestEncodeKESSigningKey(t *testing.T) {
	key := make([]byte, 64)
	encoded, err := encodeKESSigningKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "kes_sk"),
	)
}

func TestEncodeKESVerificationKey(t *testing.T) {
	key := make([]byte, 32)
	encoded, err := encodeKESVerificationKey(key)
	require.NoError(t, err)
	assert.True(
		t,
		strings.HasPrefix(encoded, "kes_vk"),
	)
}
