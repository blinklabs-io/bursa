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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenStakeAddr is the mainnet stake (reward) address derived from the
// "abandon" test mnemonic, used as a pool reward account.
const goldenStakeAddr = "stake1u8j40zgr2gy4788kl54h6x3gu0pukq5lfr8nflufpg5dzaskqlx2l"

// testVRFVKeyCborHex is an arbitrary 32-byte VRF verification key in the
// cardano-cli JSON envelope cborHex format.
const testVRFVKeyCborHex = "5820" +
	"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// --- Calidus key command ------------------------------------------------

func TestRunKeyCalidus_Bech32Output(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunKeyCalidus(testKeyMnemonic, "", "", "", "", 0, 0)
		require.NoError(t, err)
	})
	assert.True(
		t,
		strings.HasPrefix(output, "calidus_xsk"),
		"Calidus key should start with calidus_xsk prefix, got %q",
		output,
	)
}

func TestRunKeyCalidus_MissingMnemonic(t *testing.T) {
	err := RunKeyCalidus("", "", "", "", "", 0, 0)
	assert.Error(t, err)
}

func TestRunKeyCalidus_KeyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	skey := filepath.Join(tmpDir, "calidus.skey")
	vkey := filepath.Join(tmpDir, "calidus.vkey")

	err := RunKeyCalidus(testKeyMnemonic, "", "", skey, vkey, 0, 0)
	require.NoError(t, err)

	skeyData, err := os.ReadFile(skey)
	require.NoError(t, err)
	assert.Contains(t, string(skeyData), "CalidusSigningKeyShelley_ed25519")

	vkeyData, err := os.ReadFile(vkey)
	require.NoError(t, err)
	assert.Contains(
		t,
		string(vkeyData),
		"CalidusVerificationKeyShelley_ed25519",
	)
}

func TestEncodeCalidusKey(t *testing.T) {
	// 96-byte extended private key material (64 privkey || 32 chaincode).
	key := make([]byte, 96)
	for i := range key {
		key[i] = byte(i)
	}
	encoded, err := encodeCalidusKey(key)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(encoded, "calidus_xsk"))
}

// --- Pool registration certificate --------------------------------------

func TestRunCertPoolRegistration_FileOutput(t *testing.T) {
	tmpDir := t.TempDir()
	coldVkey := createTestVkeyFile(
		t, tmpDir, "cold.vkey",
		"StakePoolVerificationKey_ed25519",
		"Stake Pool Operator Verification Key",
		testColdVKeyCborHex,
	)
	vrfVkey := createTestVkeyFile(
		t, tmpDir, "vrf.vkey",
		"VrfVerificationKey_PraosVRF",
		"VRF Verification Key",
		testVRFVKeyCborHex,
	)
	outFile := filepath.Join(tmpDir, "pool-reg.cert")

	err := RunCertPoolRegistration(
		coldVkey, vrfVkey, goldenStakeAddr, outFile,
		1_000_000_000, 340_000_000, 0.03, "", "",
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var env map[string]string
	require.NoError(t, json.Unmarshal(data, &env))
	assert.Equal(t, "CertificateShelley", env["type"])
	assert.Equal(
		t,
		"Stake Pool Registration Certificate",
		env["description"],
	)
	assert.NotEmpty(t, env["cborHex"])
}

func TestRunCertPoolRegistration_StdoutWithMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	coldVkey := createTestVkeyFile(
		t, tmpDir, "cold.vkey",
		"StakePoolVerificationKey_ed25519",
		"Stake Pool Operator Verification Key",
		testColdVKeyCborHex,
	)
	vrfVkey := createTestVkeyFile(
		t, tmpDir, "vrf.vkey",
		"VrfVerificationKey_PraosVRF",
		"VRF Verification Key",
		testVRFVKeyCborHex,
	)
	metaHash := strings.Repeat("ab", 32)

	output := captureStdout(t, func() {
		err := RunCertPoolRegistration(
			coldVkey, vrfVkey, goldenStakeAddr, "",
			1_000_000, 0, 0.0, "https://example.com/p.json", metaHash,
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "Pool ID:")
	assert.Contains(t, output, "CBOR hex:")
}

func TestRunCertPoolRegistration_InvalidMargin(t *testing.T) {
	err := RunCertPoolRegistration(
		"cold.vkey", "vrf.vkey", goldenStakeAddr, "",
		1, 1, 1.5, "", "",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "margin")
}

func TestRunCertPoolRegistration_MetadataPairing(t *testing.T) {
	err := RunCertPoolRegistration(
		"cold.vkey", "vrf.vkey", goldenStakeAddr, "",
		1, 1, 0.03, "https://example.com/p.json", "",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata")
}

func TestRunCertPoolRegistration_MissingColdVkey(t *testing.T) {
	err := RunCertPoolRegistration(
		filepath.Join(t.TempDir(), "nope.vkey"), "vrf.vkey",
		goldenStakeAddr, "", 1, 1, 0.03, "", "",
	)
	require.Error(t, err)
}

// --- Pool retirement certificate ----------------------------------------

func TestRunCertPoolRetirement_FileOutput(t *testing.T) {
	tmpDir := t.TempDir()
	coldVkey := createTestVkeyFile(
		t, tmpDir, "cold.vkey",
		"StakePoolVerificationKey_ed25519",
		"Stake Pool Operator Verification Key",
		testColdVKeyCborHex,
	)
	outFile := filepath.Join(tmpDir, "pool-ret.cert")

	err := RunCertPoolRetirement(coldVkey, outFile, 300)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var env map[string]string
	require.NoError(t, json.Unmarshal(data, &env))
	assert.Equal(t, "CertificateShelley", env["type"])
	assert.Equal(
		t,
		"Stake Pool Retirement Certificate",
		env["description"],
	)
	assert.NotEmpty(t, env["cborHex"])
}

func TestRunCertPoolRetirement_Stdout(t *testing.T) {
	tmpDir := t.TempDir()
	coldVkey := createTestVkeyFile(
		t, tmpDir, "cold.vkey",
		"StakePoolVerificationKey_ed25519",
		"Stake Pool Operator Verification Key",
		testColdVKeyCborHex,
	)
	output := captureStdout(t, func() {
		err := RunCertPoolRetirement(coldVkey, "", 42)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "Epoch:")
	assert.Contains(t, output, "CBOR hex:")
}

func TestRunCertPoolRetirement_MissingColdVkey(t *testing.T) {
	err := RunCertPoolRetirement(
		filepath.Join(t.TempDir(), "nope.vkey"), "", 1,
	)
	require.Error(t, err)
}

// --- VRF verification key parsing ---------------------------------------

func TestParseVRFVerificationKey_Envelope(t *testing.T) {
	env := `{"type":"VrfVerificationKey_PraosVRF",` +
		`"description":"VRF Verification Key",` +
		`"cborHex":"` + testVRFVKeyCborHex + `"}`
	key, err := parseVRFVerificationKey([]byte(env))
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestParseVRFVerificationKey_Hex(t *testing.T) {
	hexKey := strings.Repeat("cd", 32)
	key, err := parseVRFVerificationKey([]byte(hexKey))
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestParseVRFVerificationKey_Invalid(t *testing.T) {
	_, err := parseVRFVerificationKey([]byte("not-a-key"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid VRF verification key format")
}

func TestParseVRFVerificationKey_WrongLength(t *testing.T) {
	// Envelope with a CBOR bytestring of the wrong length.
	env := `{"cborHex":"58021234"}`
	_, err := parseVRFVerificationKey([]byte(env))
	require.Error(t, err)
}

// --- margin float -> rational helpers -----------------------------------

func TestFloatToRational(t *testing.T) {
	tests := []struct {
		in        float64
		wantNum   int64
		wantDenom int64
	}{
		{0.0, 0, 1},
		{1.0, 1, 1},
		{0.03, 3, 100},
		{0.5, 1, 2},
		{0.0001, 1, 10000},
	}
	for _, tc := range tests {
		num, denom := floatToRational(tc.in)
		assert.Equal(t, tc.wantNum, num, "num for %v", tc.in)
		assert.Equal(t, tc.wantDenom, denom, "denom for %v", tc.in)
	}
}

func TestGCD(t *testing.T) {
	assert.Equal(t, int64(4), gcd(8, 12))
	assert.Equal(t, int64(1), gcd(7, 13))
	assert.Equal(t, int64(5), gcd(5, 0))
}

func TestAbs64(t *testing.T) {
	assert.Equal(t, int64(5), abs64(5))
	assert.Equal(t, int64(5), abs64(-5))
	assert.Equal(t, int64(0), abs64(0))
}

// --- Address listing -----------------------------------------------------

func TestRunAddressList(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunAddressList(testKeyMnemonic, "", "", "mainnet", 0, 0, 3)
		require.NoError(t, err)
	})
	// Output is a JSON array of derived addresses.
	var addrs []map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &addrs))
	assert.Len(t, addrs, 3)
}

func TestRunAddressList_MissingMnemonic(t *testing.T) {
	err := RunAddressList("", "", "", "mainnet", 0, 0, 1)
	assert.Error(t, err)
}
