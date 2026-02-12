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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestVkeyFile creates a test verification key file
// in cardano-cli JSON text envelope format.
func createTestVkeyFile(
	t *testing.T,
	dir, name, keyType, description, cborHex string,
) string {
	t.Helper()
	path := filepath.Join(dir, name)
	envelope := map[string]string{
		"type":        keyType,
		"description": description,
		"cborHex":     cborHex,
	}
	data, err := json.Marshal(envelope)
	require.NoError(t, err)
	err = os.WriteFile(path, data, 0o600)
	require.NoError(t, err)
	return path
}

// Test stake verification key cborHex (32-byte public key,
// CBOR-encoded). This is a deterministic test key derived
// from the "abandon" test mnemonic.
const testStakeVKeyCborHex = "5820839350412a3ec4d9aad93039bec2899562184b5ea9babb8595a6f127d48afb29"

// Test DRep verification key cborHex (arbitrary 32-byte key)
const testDRepVKeyCborHex = "5820" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// Test committee cold verification key cborHex
const testColdVKeyCborHex = "5820" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// Test committee hot verification key cborHex
const testHotVKeyCborHex = "5820" +
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func TestRunCertStakeRegistration(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test stake vkey file
	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	// Create output file
	outFile := filepath.Join(tmpDir, "stake-reg.cert")

	err := RunCertStakeRegistration(vkeyFile, outFile)
	require.NoError(t, err)

	// Verify the output file exists and has correct format
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateShelley",
		envelope["type"],
	)
	assert.Equal(
		t,
		"Stake Address Registration Certificate",
		envelope["description"],
	)
	assert.NotEmpty(t, envelope["cborHex"])
}

func TestRunCertStakeDeregistration(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "stake-dereg.cert")

	err := RunCertStakeDeregistration(vkeyFile, outFile)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateShelley",
		envelope["type"],
	)
	assert.Equal(
		t,
		"Stake Address Deregistration Certificate",
		envelope["description"],
	)
	assert.NotEmpty(t, envelope["cborHex"])
}

func TestRunCertStakeDelegation(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "stake-deleg.cert")

	// Use a 28-byte hex pool ID
	poolID := "0000000000000000000000000000000000000000000000000000000a"

	err := RunCertStakeDelegation(
		vkeyFile, poolID, outFile,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateShelley",
		envelope["type"],
	)
	assert.Equal(
		t,
		"Stake Delegation Certificate",
		envelope["description"],
	)
	assert.NotEmpty(t, envelope["cborHex"])
}

func TestRunCertStakeDelegation_InvalidPoolID(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "stake-deleg.cert")

	// Use an invalid pool ID (too short)
	err := RunCertStakeDelegation(
		vkeyFile, "deadbeef", outFile,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid pool ID")
}

func TestRunCertDRepRegistration(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "drep.vkey",
		"DRepVerificationKeyShelley_ed25519",
		"DRep Verification Key",
		testDRepVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "drep-reg.cert")

	err := RunCertDRepRegistration(
		vkeyFile, outFile,
		500000000,
		"", "",
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
	assert.Equal(
		t,
		"DRep Registration Certificate",
		envelope["description"],
	)
	assert.NotEmpty(t, envelope["cborHex"])
}

func TestRunCertDRepRegistration_WithAnchor(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "drep.vkey",
		"DRepVerificationKeyShelley_ed25519",
		"DRep Verification Key",
		testDRepVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "drep-reg.cert")

	anchorHash := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	err := RunCertDRepRegistration(
		vkeyFile, outFile,
		500000000,
		"https://example.com/drep.json",
		anchorHash,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
}

func TestRunCertDRepRegistration_AnchorURLWithoutHash(
	t *testing.T,
) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "drep.vkey",
		"DRepVerificationKeyShelley_ed25519",
		"DRep Verification Key",
		testDRepVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "drep-reg.cert")

	err := RunCertDRepRegistration(
		vkeyFile, outFile,
		500000000,
		"https://example.com/drep.json",
		"",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "anchor-hash is required")
}

func TestRunCertDRepDeregistration(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "drep.vkey",
		"DRepVerificationKeyShelley_ed25519",
		"DRep Verification Key",
		testDRepVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "drep-dereg.cert")

	err := RunCertDRepDeregistration(
		vkeyFile, outFile, 500000000,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
	assert.Equal(
		t,
		"DRep Retirement (Deregistration) Certificate",
		envelope["description"],
	)
}

func TestRunCertVoteDelegation_AlwaysAbstain(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "vote-deleg.cert")

	err := RunCertVoteDelegation(
		vkeyFile, "", "", outFile,
		true, false,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
	assert.Equal(
		t,
		"Vote Delegation Certificate",
		envelope["description"],
	)
}

func TestRunCertVoteDelegation_AlwaysNoConfidence(
	t *testing.T,
) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "vote-deleg.cert")

	err := RunCertVoteDelegation(
		vkeyFile, "", "", outFile,
		false, true,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
}

func TestRunCertVoteDelegation_DRepKeyHash(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "vote-deleg.cert")

	// 28-byte hex DRep key hash
	drepHash := "d88b9f136cc94612ed33dd8774c6f43d" +
		"b347ae5814d8efd725d39313"

	err := RunCertVoteDelegation(
		vkeyFile, drepHash, "", outFile,
		false, false,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
}

func TestRunCertVoteDelegation_NoTarget(t *testing.T) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "vote-deleg.cert")

	err := RunCertVoteDelegation(
		vkeyFile, "", "", outFile,
		false, false,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one of")
}

func TestRunCertVoteDelegation_MultipleTargets(
	t *testing.T,
) {
	tmpDir := t.TempDir()

	vkeyFile := createTestVkeyFile(
		t, tmpDir, "stake.vkey",
		"StakeVerificationKeyShelley_ed25519",
		"Stake Verification Key",
		testStakeVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "vote-deleg.cert")

	// Providing both always-abstain and always-no-confidence
	err := RunCertVoteDelegation(
		vkeyFile, "", "", outFile,
		true, true,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one of")
}

func TestRunCertCommitteeHotAuth(t *testing.T) {
	tmpDir := t.TempDir()

	coldVkeyFile := createTestVkeyFile(
		t, tmpDir, "cc-cold.vkey",
		"CommitteeColdVerificationKeyShelley_ed25519",
		"Committee Cold Verification Key",
		testColdVKeyCborHex,
	)

	hotVkeyFile := createTestVkeyFile(
		t, tmpDir, "cc-hot.vkey",
		"CommitteeHotVerificationKeyShelley_ed25519",
		"Committee Hot Verification Key",
		testHotVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "cc-hot-auth.cert")

	err := RunCertCommitteeHotAuth(
		coldVkeyFile, hotVkeyFile, outFile,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
	assert.Equal(
		t,
		"Constitutional Committee Hot Key "+
			"Authorization Certificate",
		envelope["description"],
	)
}

func TestRunCertCommitteeColdResign(t *testing.T) {
	tmpDir := t.TempDir()

	coldVkeyFile := createTestVkeyFile(
		t, tmpDir, "cc-cold.vkey",
		"CommitteeColdVerificationKeyShelley_ed25519",
		"Committee Cold Verification Key",
		testColdVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "cc-resign.cert")

	err := RunCertCommitteeColdResign(
		coldVkeyFile, outFile, "", "",
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
	assert.Equal(
		t,
		"Constitutional Committee Cold Key "+
			"Resignation Certificate",
		envelope["description"],
	)
}

func TestRunCertCommitteeColdResign_WithAnchor(
	t *testing.T,
) {
	tmpDir := t.TempDir()

	coldVkeyFile := createTestVkeyFile(
		t, tmpDir, "cc-cold.vkey",
		"CommitteeColdVerificationKeyShelley_ed25519",
		"Committee Cold Verification Key",
		testColdVKeyCborHex,
	)

	outFile := filepath.Join(tmpDir, "cc-resign.cert")

	anchorHash := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	err := RunCertCommitteeColdResign(
		coldVkeyFile, outFile,
		"https://example.com/resign.json",
		anchorHash,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(
		t,
		"CertificateConway",
		envelope["type"],
	)
}

func TestHashVerificationKey(t *testing.T) {
	// Test with a known 32-byte key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	hash, err := hashVerificationKey(key)
	require.NoError(t, err)
	assert.Len(t, hash, 28)
}

func TestHashVerificationKey_InvalidLength(t *testing.T) {
	// Test with wrong length
	key := make([]byte, 16)
	_, err := hashVerificationKey(key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 32")
}

func TestBuildKeyCredential(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cred, err := buildKeyCredential(key)
	require.NoError(t, err)
	assert.NotEmpty(t, cred)
}

func TestBuildAnchor_Null(t *testing.T) {
	anchor, err := buildAnchor("", "")
	require.NoError(t, err)
	assert.NotEmpty(t, anchor)
	// CBOR null is 0xf6
	assert.Equal(t, byte(0xf6), anchor[0])
}

func TestBuildAnchor_WithURL(t *testing.T) {
	anchorHash := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	anchor, err := buildAnchor(
		"https://example.com/test.json",
		anchorHash,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, anchor)
}

func TestBuildAnchor_URLWithoutHash(t *testing.T) {
	_, err := buildAnchor(
		"https://example.com/test.json", "",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "anchor-hash is required")
}

func TestBuildAnchor_InvalidHashLength(t *testing.T) {
	_, err := buildAnchor(
		"https://example.com/test.json",
		"deadbeef",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 32")
}

func TestBuildAnchor_HashWithoutURL(t *testing.T) {
	anchorHash := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	_, err := buildAnchor("", anchorHash)
	assert.Error(t, err)
	assert.Contains(
		t,
		err.Error(),
		"anchor-url is required",
	)
}

func TestParsePoolID_Hex(t *testing.T) {
	hexID := "0000000000000000000000000000000000000000000000000000000a"
	hash, err := parsePoolID(hexID)
	require.NoError(t, err)
	assert.Len(t, hash, 28)
}

func TestParsePoolID_InvalidHexLength(t *testing.T) {
	_, err := parsePoolID("deadbeef")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 28")
}

func TestParseDRepID_Hex(t *testing.T) {
	hexID := "d88b9f136cc94612ed33dd8774c6f43d" +
		"b347ae5814d8efd725d39313"
	hash, err := parseDRepID(hexID)
	require.NoError(t, err)
	assert.Len(t, hash, 28)
}

func TestParseDRepID_InvalidHexLength(t *testing.T) {
	_, err := parseDRepID("deadbeef")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 28")
}

func TestBuildDRepTarget_AlwaysAbstain(t *testing.T) {
	target, err := buildDRepTarget(
		"", "", true, false,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, target)
	// CBOR encoding of uint64(2) = 0x02
	assert.Equal(t, byte(0x02), target[0])
}

func TestBuildDRepTarget_AlwaysNoConfidence(t *testing.T) {
	target, err := buildDRepTarget(
		"", "", false, true,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, target)
	// CBOR encoding of uint64(3) = 0x03
	assert.Equal(t, byte(0x03), target[0])
}

func TestBuildDRepTarget_KeyHash(t *testing.T) {
	keyHash := "d88b9f136cc94612ed33dd8774c6f43d" +
		"b347ae5814d8efd725d39313"
	target, err := buildDRepTarget(
		keyHash, "", false, false,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, target)
}

func TestBuildDRepTarget_InvalidKeyHash(t *testing.T) {
	_, err := buildDRepTarget(
		"deadbeef", "", false, false,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 28")
}

func TestRunCertStakeRegistration_MissingFile(
	t *testing.T,
) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "out.cert")

	err := RunCertStakeRegistration(
		"/nonexistent/stake.vkey", outFile,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
}

func TestWriteCertEnvelope(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "test.cert")

	err := writeCertEnvelope(
		"TestType",
		"Test Description",
		[]byte{0x01, 0x02, 0x03},
		outFile,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope map[string]string
	err = json.Unmarshal(data, &envelope)
	require.NoError(t, err)

	assert.Equal(t, "TestType", envelope["type"])
	assert.Equal(
		t, "Test Description", envelope["description"],
	)
	assert.Equal(t, "010203", envelope["cborHex"])
}
