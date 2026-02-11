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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunScriptCreate_NOf(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-script-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "script.json")
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
		"02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d",
	}

	err = RunScriptCreate(
		1, hashes, outputFile, "mainnet",
		false, false, 0, 0,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var scriptData bursa.ScriptData
	err = json.Unmarshal(data, &scriptData)
	require.NoError(t, err)
	assert.Equal(t, "NativeScript", scriptData.Type)
	assert.NotEmpty(t, scriptData.Address)
}

func TestRunScriptCreate_All(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}

	output := captureStdout(t, func() {
		err := RunScriptCreate(
			0, hashes, "", "mainnet",
			true, false, 0, 0,
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "NativeScript")
}

func TestRunScriptCreate_Any(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}

	output := captureStdout(t, func() {
		err := RunScriptCreate(
			0, hashes, "", "mainnet",
			false, true, 0, 0,
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "NativeScript")
}

func TestRunScriptCreate_BothAllAndAny(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}
	err := RunScriptCreate(
		0, hashes, "", "mainnet",
		true, true, 0, 0,
	)
	assert.Error(t, err)
	assert.Contains(
		t, err.Error(),
		"cannot specify both --all and --any",
	)
}

func TestRunScriptCreate_AllWithRequired(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}
	err := RunScriptCreate(
		1, hashes, "", "mainnet",
		true, false, 0, 0,
	)
	assert.Error(t, err)
	assert.Contains(
		t, err.Error(),
		"cannot specify --required with --all",
	)
}

func TestRunScriptCreate_AnyWithRequired(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}
	err := RunScriptCreate(
		1, hashes, "", "mainnet",
		false, true, 0, 0,
	)
	assert.Error(t, err)
	assert.Contains(
		t, err.Error(),
		"cannot specify --required with --any",
	)
}

func TestRunScriptCreate_NoTypeSpecified(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}
	err := RunScriptCreate(
		0, hashes, "", "mainnet",
		false, false, 0, 0,
	)
	assert.Error(t, err)
	assert.Contains(
		t, err.Error(),
		"must specify --required, --all, or --any",
	)
}

func TestRunScriptCreate_NoKeyHashes(t *testing.T) {
	err := RunScriptCreate(
		1, []string{}, "", "mainnet",
		false, false, 0, 0,
	)
	assert.Error(t, err)
	assert.Contains(
		t, err.Error(),
		"must provide at least one key hash",
	)
}

func TestRunScriptCreate_InvalidKeyHash(t *testing.T) {
	hashes := []string{"not-hex"}
	err := RunScriptCreate(
		1, hashes, "", "mainnet",
		false, false, 0, 0,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key hash format")
}

func TestRunScriptCreate_WrongKeyHashLength(t *testing.T) {
	hashes := []string{"0102030405"}
	err := RunScriptCreate(
		1, hashes, "", "mainnet",
		false, false, 0, 0,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key hash length")
}

func TestRunScriptCreate_RequiredExceedsKeyCount(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}
	err := RunScriptCreate(
		5, hashes, "", "mainnet",
		false, false, 0, 0,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot exceed")
}

func TestRunScriptCreate_BothTimelocks(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}
	err := RunScriptCreate(
		1, hashes, "", "mainnet",
		false, false, 1000, 500,
	)
	assert.Error(t, err)
	assert.Contains(
		t, err.Error(),
		"cannot specify both",
	)
}

func TestRunScriptCreate_WithTimelockBefore(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}

	output := captureStdout(t, func() {
		err := RunScriptCreate(
			0, hashes, "", "mainnet",
			true, false, 1000000, 0,
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "NativeScript")
}

func TestRunScriptCreate_WithTimelockAfter(t *testing.T) {
	hashes := []string{
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
	}

	output := captureStdout(t, func() {
		err := RunScriptCreate(
			0, hashes, "", "mainnet",
			true, false, 0, 500000,
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "NativeScript")
}

func TestRunAddressBuild_BaseMainnet(t *testing.T) {
	// Generate keys from the test mnemonic first
	paymentVk := "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"
	stakeVk := "stake_vk1swf4qsf28mzdn2kexqumas5fj43psj674xathpv45mcj04y2lv5scvw4uv"

	output := captureStdout(t, func() {
		err := RunAddressBuild(
			paymentVk, stakeVk, "mainnet", "base",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "addr1")
}

func TestRunAddressBuild_Enterprise(t *testing.T) {
	paymentVk := "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"

	output := captureStdout(t, func() {
		err := RunAddressBuild(
			paymentVk, "", "mainnet", "enterprise",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "addr1")
}

func TestRunAddressBuild_Reward(t *testing.T) {
	stakeVk := "stake_vk1swf4qsf28mzdn2kexqumas5fj43psj674xathpv45mcj04y2lv5scvw4uv"

	output := captureStdout(t, func() {
		err := RunAddressBuild(
			"", stakeVk, "mainnet", "reward",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "stake1")
}

func TestRunAddressBuild_Testnet(t *testing.T) {
	paymentVk := "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"
	stakeVk := "stake_vk1swf4qsf28mzdn2kexqumas5fj43psj674xathpv45mcj04y2lv5scvw4uv"

	output := captureStdout(t, func() {
		err := RunAddressBuild(
			paymentVk, stakeVk, "testnet", "base",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "addr_test1")
}

func TestRunAddressBuild_InvalidNetwork(t *testing.T) {
	paymentVk := "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"
	err := RunAddressBuild(
		paymentVk, "", "invalid", "enterprise",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid network")
}

func TestRunAddressBuild_BaseMissingStakeKey(t *testing.T) {
	paymentVk := "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"
	err := RunAddressBuild(
		paymentVk, "", "mainnet", "base",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "require both")
}

func TestRunAddressBuild_EnterpriseMissingPaymentKey(
	t *testing.T,
) {
	err := RunAddressBuild("", "", "mainnet", "enterprise")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "require a payment key")
}

func TestRunAddressBuild_RewardMissingStakeKey(t *testing.T) {
	err := RunAddressBuild("", "", "mainnet", "reward")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "require a stake key")
}

func TestRunAddressBuild_UnsupportedType(t *testing.T) {
	err := RunAddressBuild(
		"some_key", "", "mainnet", "unsupported",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported address type")
}

func TestRunAddressEnterprise_WithBech32Key(t *testing.T) {
	paymentVk := "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"

	output := captureStdout(t, func() {
		err := RunAddressEnterprise(
			paymentVk, "", "mainnet",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "addr1")
}

func TestRunAddressEnterprise_InvalidNetwork(t *testing.T) {
	paymentVk := "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"
	err := RunAddressEnterprise(paymentVk, "", "invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid network")
}

func TestRunAddressEnterprise_NoKeyProvided(t *testing.T) {
	err := RunAddressEnterprise("", "", "mainnet")
	assert.Error(t, err)
	assert.Contains(
		t, err.Error(),
		"payment key or payment key file must be specified",
	)
}

func TestRunAddressEnterprise_Testnet(t *testing.T) {
	paymentVk := "addr_vk18nqps65rh0azud77qruff3dctszahutmrhkxg87mlfny0addcles83lnyc"

	output := captureStdout(t, func() {
		err := RunAddressEnterprise(
			paymentVk, "", "testnet",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "addr_test1")
}

func TestRunAddressInfo_MainnetBaseAddress(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunAddressInfo(
			"addr1qxwqkfd3qz5pdwmemtv2llmetegdyku4ffxuldjcfrs05nfjtw33ktf3j6amgxsgnj9u3fa5nrle79nv2g24npnth0esk2dy7q",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "Base")
	assert.Contains(t, output, "mainnet")
	assert.Contains(t, output, "Payment Credential")
	assert.Contains(t, output, "Stake Credential")
}

func TestRunAddressInfo_TestnetAddress(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunAddressInfo(
			"addr_test1qqqcea9cpx0480yjvvklp0tw4yw56r6q9qc437gpqwg6swwc3w03xmxfgcfw6v7asa6vdapakdr6ukq5mrhawfwnjvfsqeaxws",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "Base")
	assert.Contains(t, output, "testnet")
}

func TestRunAddressInfo_EnterpriseAddress(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunAddressInfo(
			"addr_test1vqqcea9cpx0480yjvvklp0tw4yw56r6q9qc437gpqwg6swg560kjv",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "Enterprise")
	assert.Contains(t, output, "Payment Credential")
}

func TestRunAddressInfo_StakeAddress(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunAddressInfo(
			"stake1uye9hgcm95cedwa5rgyfez7g576f3lulzek9y92ese4mhucu439t0",
		)
		require.NoError(t, err)
	})
	assert.Contains(t, output, "Reward")
	assert.Contains(t, output, "Stake Credential")
}

func TestRunAddressInfo_InvalidAddressString(t *testing.T) {
	err := RunAddressInfo("invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid address")
}

func TestRunHashAnchorData_TextInput(t *testing.T) {
	output := captureStdout(t, func() {
		err := RunHashAnchorData(
			"test data", "", "", "", "", "",
		)
		require.NoError(t, err)
	})
	// Should produce a 64-character hex hash
	assert.Len(t, output, 64)
}

func TestRunHashAnchorData_FileTextInput(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-anchor-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(
		testFile, []byte("test file content"), 0o644,
	)
	require.NoError(t, err)

	output := captureStdout(t, func() {
		err := RunHashAnchorData(
			"", testFile, "", "", "", "",
		)
		require.NoError(t, err)
	})
	assert.Len(t, output, 64)
}

func TestRunHashAnchorData_FileBinaryInput(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-anchor-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.bin")
	err = os.WriteFile(
		testFile, []byte{0x00, 0x01, 0x02}, 0o644,
	)
	require.NoError(t, err)

	output := captureStdout(t, func() {
		err := RunHashAnchorData(
			"", "", testFile, "", "", "",
		)
		require.NoError(t, err)
	})
	assert.Len(t, output, 64)
}

func TestRunHashAnchorData_NoInput(t *testing.T) {
	err := RunHashAnchorData("", "", "", "", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no input source specified")
}

func TestRunHashAnchorData_ExpectedHash_Match(t *testing.T) {
	// First compute hash of "test data"
	hash := captureStdout(t, func() {
		err := RunHashAnchorData(
			"test data", "", "", "", "", "",
		)
		require.NoError(t, err)
	})

	// Now verify with expected hash
	err := RunHashAnchorData(
		"test data", "", "", "", hash, "",
	)
	assert.NoError(t, err)
}

func TestRunHashAnchorData_ExpectedHash_Mismatch(t *testing.T) {
	err := RunHashAnchorData(
		"test data", "", "", "",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hash verification failed")
}

func TestRunHashAnchorData_OutputToFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bursa-anchor-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	outFile := filepath.Join(tempDir, "hash.txt")
	err = RunHashAnchorData(
		"test data", "", "", "", "", outFile,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	// Hash + newline = 65 chars
	assert.Len(t, string(data), 65)
}

func TestRunHashAnchorData_NonexistentTextFile(t *testing.T) {
	err := RunHashAnchorData(
		"", "/nonexistent/file.txt", "", "", "", "",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read text file")
}

func TestRunHashAnchorData_NonexistentBinaryFile(t *testing.T) {
	err := RunHashAnchorData(
		"", "", "/nonexistent/file.bin", "", "", "",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read binary file")
}

func TestParseVerificationKey_JSONEnvelope(t *testing.T) {
	// Valid KES verification key in JSON envelope format
	// 5820 + 32 bytes of zeros
	envelope := `{
		"type": "KESVerificationKey_PraosV2",
		"description": "KES Verification Key",
		"cborHex": "5820` +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		`"
	}`

	key, err := parseVerificationKey([]byte(envelope))
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestParseVerificationKey_HexFormat(t *testing.T) {
	hexKey := "0000000000000000000000000000000000000000000000000000000000000000"
	key, err := parseVerificationKey([]byte(hexKey))
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestParseVerificationKey_InvalidFormat(t *testing.T) {
	_, err := parseVerificationKey([]byte("invalid"))
	assert.Error(t, err)
}

func TestParseSigningKey_HexFormat32(t *testing.T) {
	hexKey := "0000000000000000000000000000000000000000000000000000000000000000"
	key, err := parseSigningKey([]byte(hexKey))
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestParseSigningKey_HexFormat64(t *testing.T) {
	hexKey := "0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	key, err := parseSigningKey([]byte(hexKey))
	require.NoError(t, err)
	// Extended keys return first 32 bytes
	assert.Len(t, key, 32)
}

func TestParseSigningKey_InvalidFormat(t *testing.T) {
	_, err := parseSigningKey([]byte("invalid"))
	assert.Error(t, err)
}

func TestEncodeCredentialBech32(t *testing.T) {
	hash := make([]byte, 28)
	encoded, err := encodeCredentialBech32(hash, "addr_vkh")
	require.NoError(t, err)
	assert.True(
		t,
		len(encoded) > 0,
		"encoded credential should not be empty",
	)
}

func TestParseBech32VerificationKey_InvalidBech32(t *testing.T) {
	_, err := parseBech32VerificationKey("not-bech32", true)
	assert.Error(t, err)
}

func TestParseBech32VerificationKey_WrongHRP(t *testing.T) {
	// Use a valid bech32 string but with wrong HRP
	_, err := parseBech32VerificationKey(
		"stake_vk1swf4qsf28mzdn2kexqumas5fj43psj674xathpv45mcj04y2lv5scvw4uv",
		true, // expecting payment key
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key type")
}
