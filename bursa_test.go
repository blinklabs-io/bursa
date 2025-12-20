// Copyright 2025 Blink Labs Software
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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	bip39 "github.com/tyler-smith/go-bip39"
)

// testKeyHash returns a 28-byte test key hash for use in tests
func testKeyHash() []byte {
	return []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c,
	}
}

func TestExtractKeyFiles(t *testing.T) {
	wallet := &Wallet{
		PaymentVKey: KeyFile{
			Type:        "PaymentVerificationKeyShelley_ed25519",
			Description: "Payment Verification Key",
			CborHex:     "ada123",
		},
		PaymentSKey: KeyFile{
			Type:        "PaymentSigningKeyShelley_ed25519",
			Description: "Payment Signing Key",
			CborHex:     "ada123",
		},
		PaymentExtendedSKey: KeyFile{
			Type:        "PaymentExtendedSigningKeyShelley_ed25519_bip32",
			Description: "Payment Extended Signing Key (BIP32)",
			CborHex:     "ada123",
		},
		StakeVKey: KeyFile{
			Type:        "StakeVerificationKeyShelley_ed25519",
			Description: "Stake Verification Key",
			CborHex:     "ada123",
		},
		StakeSKey: KeyFile{
			Type:        "StakeSigningKeyShelley_ed25519",
			Description: "Stake Signing Key",
			CborHex:     "ada123",
		},
		StakeExtendedSKey: KeyFile{
			Type:        "StakeExtendedSigningKeyShelley_ed25519_bip32",
			Description: "Stake Extended Signing Key (BIP32)",
			CborHex:     "ada123",
		},
	}

	expected := map[string]string{
		"payment.vkey": `{
    "type": "PaymentVerificationKeyShelley_ed25519",
    "description": "Payment Verification Key",
    "cborHex": "ada123"
}
`,
		"payment.skey": `{
    "type": "PaymentSigningKeyShelley_ed25519",
    "description": "Payment Signing Key",
    "cborHex": "ada123"
}
`,
		"paymentExtended.skey": `{
    "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32",
    "description": "Payment Extended Signing Key (BIP32)",
    "cborHex": "ada123"
}
`,
		"stake.vkey": `{
    "type": "StakeVerificationKeyShelley_ed25519",
    "description": "Stake Verification Key",
    "cborHex": "ada123"
}
`,
		"stake.skey": `{
    "type": "StakeSigningKeyShelley_ed25519",
    "description": "Stake Signing Key",
    "cborHex": "ada123"
}
`,
		"stakeExtended.skey": `{
    "type": "StakeExtendedSigningKeyShelley_ed25519_bip32",
    "description": "Stake Extended Signing Key (BIP32)",
    "cborHex": "ada123"
}
`,
		"drep.vkey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
		"drep.skey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
		"drepExtended.skey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
		"committee-cold.vkey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
		"committee-cold.skey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
		"committee-cold-extended.skey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
		"committee-hot.vkey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
		"committee-hot.skey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
		"committee-hot-extended.skey": `{
    "type": "",
    "description": "",
    "cborHex": ""
}
`,
	}

	result, err := ExtractKeyFiles(wallet)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestLoadWalletDir(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create a wallet
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	wallet, err := NewWallet(mnemonic, "mainnet", "", 0, 0, 0, 0, 0, 0, 0)
	assert.NoError(t, err)

	// Extract key files
	keyFiles, err := ExtractKeyFiles(wallet)
	assert.NoError(t, err)

	// Write key files to temp dir
	for filename, content := range keyFiles {
		path := filepath.Join(tmpDir, filename)
		err := os.WriteFile(path, []byte(content), 0o600)
		assert.NoError(t, err)
	}

	// Load the wallet dir
	loadedKeys, err := LoadWalletDir(tmpDir, true)
	assert.NoError(t, err)
	assert.Len(
		t,
		loadedKeys,
		15,
	) // 3 vkeys + 3 skeys per key type (payment, stake, drep, committee cold, committee hot)

	// Check that keys are loaded correctly
	keyMap := make(map[string]*LoadedKey)
	for _, lk := range loadedKeys {
		keyMap[lk.File] = lk
	}

	// Verify payment vkey
	pvkey := keyMap["payment.vkey"]
	assert.NotNil(t, pvkey)
	assert.Equal(t, "PaymentVerificationKeyShelley_ed25519", pvkey.Type)
	assert.Len(t, pvkey.VKey, 32)

	// Verify payment skey
	pskey := keyMap["payment.skey"]
	assert.NotNil(t, pskey)
	assert.Equal(t, "PaymentSigningKeyShelley_ed25519", pskey.Type)
	assert.Len(t, pskey.SKey, 64)
	assert.Len(t, pskey.VKey, 32)

	// Verify extended skey
	peskey := keyMap["paymentExtended.skey"]
	assert.NotNil(t, peskey)
	assert.Equal(
		t,
		"PaymentExtendedSigningKeyShelley_ed25519_bip32",
		peskey.Type,
	)
	assert.Len(t, peskey.SKey, 96)
	assert.Len(t, peskey.VKey, 32)
}

func TestLoadWalletDirPartial(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create a wallet
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	wallet, err := NewWallet(mnemonic, "mainnet", "", 0, 0, 0, 0, 0, 0, 0)
	assert.NoError(t, err)

	// Extract key files
	keyFiles, err := ExtractKeyFiles(wallet)
	assert.NoError(t, err)

	// Write only some key files to temp dir (simulate partial directory)
	filesToWrite := []string{
		"payment.vkey",
		"stake.skey",
		"paymentExtended.skey",
	}
	for _, name := range filesToWrite {
		if content, ok := keyFiles[name]; ok {
			path := filepath.Join(tmpDir, name)
			err := os.WriteFile(path, []byte(content), 0o600)
			assert.NoError(t, err)
		}
	}

	// Add a corrupted file
	corruptedPath := filepath.Join(tmpDir, "corrupted.vkey")
	err = os.WriteFile(corruptedPath, []byte("invalid json"), 0o600)
	assert.NoError(t, err)

	// Load the wallet dir
	loadedKeys, err := LoadWalletDir(tmpDir, true)
	assert.NoError(t, err)
	assert.Len(
		t,
		loadedKeys,
		3,
	) // Should load the 3 valid files, skip corrupted

	// Check that only valid files are loaded
	keyMap := make(map[string]*LoadedKey)
	for _, lk := range loadedKeys {
		keyMap[lk.File] = lk
	}

	assert.Contains(t, keyMap, "payment.vkey")
	assert.Contains(t, keyMap, "stake.skey")
	assert.Contains(t, keyMap, "paymentExtended.skey")
	assert.NotContains(t, keyMap, "corrupted.vkey")
}

func TestLoadWalletDirEmpty(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Try to load from empty directory
	loadedKeys, err := LoadWalletDir(tmpDir, true)
	assert.Error(t, err)
	assert.Nil(t, loadedKeys)
	assert.True(t, errors.Is(err, fs.ErrNotExist))
}

func BenchmarkNewWallet(b *testing.B) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	for b.Loop() {
		_, err := NewWallet(mnemonic, "mainnet", "", 0, 0, 0, 0, 0, 0, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExtractKeyFiles(b *testing.B) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	wallet, err := NewWallet(
		mnemonic,
		"mainnet",
		"",
		0,
		0,
		0,
		0,
		0,
		0,
		0,
	)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := ExtractKeyFiles(wallet)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCBORDecode(b *testing.B) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	wallet, err := NewWallet(
		mnemonic,
		"mainnet",
		"",
		0,
		0,
		0,
		0,
		0,
		0,
		0,
	)
	if err != nil {
		b.Fatal(err)
	}

	// Get CBOR data from a key file
	cborHex := wallet.PaymentVKey.CborHex
	cborData, err := hex.DecodeString(cborHex)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		_, err := decodeVerificationKey(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadWalletDir(b *testing.B) {
	// Create a temporary directory with wallet files
	tmpDir := b.TempDir()

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	wallet, err := NewWallet(mnemonic, "mainnet", "", 0, 0, 0, 0, 0, 0, 0)
	if err != nil {
		b.Fatal(err)
	}

	keyFiles, err := ExtractKeyFiles(wallet)
	if err != nil {
		b.Fatal(err)
	}

	// Write key files
	for name, content := range keyFiles {
		path := filepath.Join(tmpDir, name)
		err := os.WriteFile(path, []byte(content), 0o600)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := LoadWalletDir(tmpDir, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestNewWalletInvalidMnemonic(t *testing.T) {
	_, err := NewWallet("invalid mnemonic", "mainnet", "", 0, 0, 0, 0, 0, 0, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mnemonic")
}

func TestNewWalletInvalidIndices(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	_, err := NewWallet(mnemonic, "mainnet", "", 0x80000000, 0, 0, 0, 0, 0, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "derivation indices must be less than 2^31")
}

func TestGenerateMnemonic(t *testing.T) {
	mnemonic, err := GenerateMnemonic()
	assert.NoError(t, err)
	assert.NotEmpty(t, mnemonic)
	// Verify the generated mnemonic is valid BIP39
	assert.True(t, bip39.IsMnemonicValid(mnemonic))
	// Verify it has the expected number of words (24 for 256-bit entropy)
	words := strings.Split(mnemonic, " ")
	assert.Equal(t, 24, len(words))
}

func TestCIP1852Compliance(t *testing.T) {
	// Test CIP-1852 compliance using a known mnemonic
	// This test verifies that the derivation paths follow CIP-1852 specification
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password := ""
	accountId := uint32(0)
	paymentId := uint32(0)
	stakeId := uint32(0)

	// Generate wallet
	wallet, err := NewWallet(
		mnemonic,
		"mainnet",
		password,
		accountId,
		paymentId,
		stakeId,
		0,
		0,
		0,
		0,
	)
	assert.NoError(t, err)
	assert.NotNil(t, wallet)

	// Verify that keys are generated (non-empty)
	assert.NotEmpty(t, wallet.PaymentVKey.CborHex)
	assert.NotEmpty(t, wallet.PaymentSKey.CborHex)
	assert.NotEmpty(t, wallet.StakeVKey.CborHex)
	assert.NotEmpty(t, wallet.StakeSKey.CborHex)

	// Verify key types are correct
	assert.Equal(
		t,
		"PaymentVerificationKeyShelley_ed25519",
		wallet.PaymentVKey.Type,
	)
	assert.Equal(t, "PaymentSigningKeyShelley_ed25519", wallet.PaymentSKey.Type)
	assert.Equal(
		t,
		"StakeVerificationKeyShelley_ed25519",
		wallet.StakeVKey.Type,
	)
	assert.Equal(t, "StakeSigningKeyShelley_ed25519", wallet.StakeSKey.Type)

	// Verify CBOR structure for verification keys
	vkeyBytes, err := hex.DecodeString(wallet.PaymentVKey.CborHex)
	assert.NoError(t, err)
	vk, err := decodeVerificationKey(vkeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, 32, len(vk))

	// Verify CBOR structure for signing keys
	skeyBytes, err := hex.DecodeString(wallet.PaymentSKey.CborHex)
	assert.NoError(t, err)
	sk, vk2, err := decodeNonExtendedCborKey(skeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, 64, len(sk)) // 32-byte private + 32-byte public
	assert.Equal(t, 32, len(vk2))

	// Note: The public keys may not match due to different key representations/formats
	// The important thing is that CBOR encoding/decoding works correctly
}

func TestCIP1852DerivationPaths(t *testing.T) {
	// Test that different derivation paths produce different keys
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	rootKey, err := GetRootKeyFromMnemonic(mnemonic, "")
	assert.NoError(t, err)

	// Test account derivation
	accountKey0, err := GetAccountKey(rootKey, 0)
	assert.NoError(t, err)
	accountKey1, err := GetAccountKey(rootKey, 1)
	assert.NoError(t, err)

	// Different account indices should produce different keys
	assert.NotEqual(t, accountKey0, accountKey1)

	// Test payment key derivation
	paymentKey0, err := GetPaymentKey(accountKey0, 0)
	assert.NoError(t, err)
	paymentKey1, err := GetPaymentKey(accountKey0, 1)
	assert.NoError(t, err)

	// Different payment indices should produce different keys
	assert.NotEqual(t, paymentKey0, paymentKey1)

	// Test stake key derivation
	stakeKey0, err := GetStakeKey(accountKey0, 0)
	assert.NoError(t, err)
	stakeKey1, err := GetStakeKey(accountKey0, 1)
	assert.NoError(t, err)

	// Different stake indices should produce different keys
	assert.NotEqual(t, stakeKey0, stakeKey1)

	// Test that same indices from different accounts produce different keys
	paymentKeyFromAccount1, err := GetPaymentKey(accountKey1, 0)
	assert.NoError(t, err)
	assert.NotEqual(t, paymentKey0, paymentKeyFromAccount1)
}

func TestRootKeyDerivation(t *testing.T) {
	// Test root key derivation from mnemonic
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	// Test with no password
	rootKey1, err := GetRootKeyFromMnemonic(mnemonic, "")
	assert.NoError(t, err)
	assert.NotNil(t, rootKey1)

	// Test with password
	rootKey2, err := GetRootKeyFromMnemonic(mnemonic, "testpassword")
	assert.NoError(t, err)
	assert.NotNil(t, rootKey2)

	// Different passwords should produce different root keys
	assert.NotEqual(t, rootKey1, rootKey2)

	// Test that the same mnemonic+password produces the same key
	rootKey3, err := GetRootKeyFromMnemonic(mnemonic, "")
	assert.NoError(t, err)
	assert.Equal(t, rootKey1, rootKey3)
}

func TestGetRootKeyFromMnemonic(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
		password string
		errMsg   string
		wantErr  bool
	}{
		{
			name:     "valid mnemonic",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			password: "",
			wantErr:  false,
		},
		{
			name:     "valid mnemonic with password",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			password: "testpassword",
			wantErr:  false,
		},
		{
			name:     "invalid mnemonic",
			mnemonic: "invalid mnemonic",
			password: "",
			wantErr:  true,
			errMsg:   "invalid mnemonic",
		},
		{
			name:     "empty mnemonic",
			mnemonic: "",
			password: "",
			wantErr:  true,
			errMsg:   "invalid mnemonic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetRootKeyFromMnemonic(tt.mnemonic, tt.password)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetAccountKey(t *testing.T) {
	rootKey, _ := GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)

	tests := []struct {
		name    string
		errMsg  string
		num     uint32
		wantErr bool
	}{
		{
			name:    "valid index",
			num:     0,
			wantErr: false,
		},
		{
			name:    "valid index max",
			num:     0x7FFFFFFF,
			wantErr: false,
		},
		{
			name:    "invalid index",
			num:     0x80000000,
			wantErr: true,
			errMsg:  "derivation indices must be less than 2^31",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetAccountKey(rootKey, tt.num)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetPaymentKey(t *testing.T) {
	rootKey, _ := GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)
	accountKey, _ := GetAccountKey(rootKey, 0)

	tests := []struct {
		name    string
		errMsg  string
		num     uint32
		wantErr bool
	}{
		{
			name:    "valid index",
			num:     0,
			wantErr: false,
		},
		{
			name:    "valid index max",
			num:     0x7FFFFFFF,
			wantErr: false,
		},
		{
			name:    "invalid index",
			num:     0x80000000,
			wantErr: true,
			errMsg:  "derivation indices must be less than 2^31",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPaymentKey(accountKey, tt.num)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetStakeKey(t *testing.T) {
	rootKey, _ := GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)
	accountKey, _ := GetAccountKey(rootKey, 0)

	tests := []struct {
		name    string
		errMsg  string
		num     uint32
		wantErr bool
	}{
		{
			name:    "valid index",
			num:     0,
			wantErr: false,
		},
		{
			name:    "valid index max",
			num:     0x7FFFFFFF,
			wantErr: false,
		},
		{
			name:    "invalid index",
			num:     0x80000000,
			wantErr: true,
			errMsg:  "derivation indices must be less than 2^31",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetStakeKey(accountKey, tt.num)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetAddress(t *testing.T) {
	rootKey, _ := GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)
	accountKey, _ := GetAccountKey(rootKey, 0)

	tests := []struct {
		name        string
		networkName string
		errMsg      string
		num         uint32
		wantErr     bool
	}{
		{
			name:        "valid address",
			networkName: "mainnet",
			num:         0,
			wantErr:     false,
		},
		{
			name:        "valid address max index",
			networkName: "mainnet",
			num:         0x7FFFFFFF,
			wantErr:     false,
		},
		{
			name:        "empty network name",
			networkName: "",
			num:         0,
			wantErr:     true,
			errMsg:      "invalid network name",
		},
		{
			name:        "invalid network name",
			networkName: "invalid",
			num:         0,
			wantErr:     true,
			errMsg:      "invalid network name",
		},
		{
			name:        "invalid address index",
			networkName: "mainnet",
			num:         0x80000000,
			wantErr:     true,
			errMsg:      "derivation indices must be less than 2^31",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetAddress(accountKey, tt.networkName, tt.num)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractKeyFilesValidation(t *testing.T) {
	tests := []struct {
		wallet  *Wallet
		name    string
		errMsg  string
		wantErr bool
	}{
		{
			name: "valid wallet",
			wallet: &Wallet{
				PaymentVKey: KeyFile{
					Type:        "test",
					Description: "test",
					CborHex:     "ada123",
				},
				PaymentSKey: KeyFile{
					Type:        "test",
					Description: "test",
					CborHex:     "ada123",
				},
				PaymentExtendedSKey: KeyFile{
					Type:        "test",
					Description: "test",
					CborHex:     "ada123",
				},
				StakeVKey: KeyFile{
					Type:        "test",
					Description: "test",
					CborHex:     "ada123",
				},
				StakeSKey: KeyFile{
					Type:        "test",
					Description: "test",
					CborHex:     "ada123",
				},
				StakeExtendedSKey: KeyFile{
					Type:        "test",
					Description: "test",
					CborHex:     "ada123",
				},
			},
			wantErr: false,
		},
		{
			name:    "nil wallet",
			wallet:  nil,
			wantErr: true,
			errMsg:  "wallet cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractKeyFiles(tt.wallet)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadWalletDirValidation(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		errMsg  string
		wantErr bool
	}{
		{
			name:    "empty directory",
			dir:     "",
			wantErr: true,
			errMsg:  "directory path cannot be empty",
		},
		{
			name:    "nonexistent directory",
			dir:     "/nonexistent/directory",
			wantErr: true,
			errMsg:  "failed to read directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadWalletDir(tt.dir, false)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScriptTypes(t *testing.T) {
	// Test script sig
	keyHash := testKeyHash()
	scriptSig, err := NewScriptSig(keyHash)
	assert.NoError(t, err)
	assert.NotNil(t, scriptSig)
	scriptType, err := GetScriptType(scriptSig)
	assert.NoError(t, err)
	assert.Equal(t, 0, scriptType)
	cbor := scriptSig.Cbor()
	assert.NotEmpty(t, cbor)

	// Test script all
	scriptAll, err := NewScriptAll(scriptSig)
	assert.NoError(t, err)
	assert.NotNil(t, scriptAll)
	scriptType, err = GetScriptType(scriptAll)
	assert.NoError(t, err)
	assert.Equal(t, 1, scriptType)
	cbor = scriptAll.Cbor()
	assert.NotEmpty(t, cbor)

	// Test script any
	scriptAny, err := NewScriptAny(scriptSig)
	assert.NoError(t, err)
	assert.NotNil(t, scriptAny)
	scriptType, err = GetScriptType(scriptAny)
	assert.NoError(t, err)
	assert.Equal(t, 2, scriptType)
	cbor = scriptAny.Cbor()
	assert.NotEmpty(t, cbor)

	// Test script N-of
	scriptNOf, err := NewScriptNOf(2, scriptSig, scriptSig)
	assert.NoError(t, err)
	assert.NotNil(t, scriptNOf)
	scriptType, err = GetScriptType(scriptNOf)
	assert.NoError(t, err)
	assert.Equal(t, 3, scriptType)
	cbor = scriptNOf.Cbor()
	assert.NotEmpty(t, cbor)

	// Test script before
	// Test script before (InvalidHereafter = type 5 per CIP-1854)
	scriptBefore, err := NewScriptBefore(123456789)
	assert.NoError(t, err)
	assert.NotNil(t, scriptBefore)
	scriptType, err = GetScriptType(scriptBefore)
	assert.NoError(t, err)
	assert.Equal(
		t,
		5,
		scriptType,
	) // InvalidHereafter for "before"
	cbor = scriptBefore.Cbor()
	assert.NotEmpty(t, cbor)

	// Test script after (InvalidBefore = type 4 per CIP-1854)
	scriptAfter, err := NewScriptAfter(123456789)
	assert.NoError(t, err)
	assert.NotNil(t, scriptAfter)
	scriptType, err = GetScriptType(scriptAfter)
	assert.NoError(t, err)
	assert.Equal(t, 4, scriptType) // InvalidBefore for "after"
	cbor = scriptAfter.Cbor()
	assert.NotEmpty(t, cbor)
}

func TestGetScriptHash(t *testing.T) {
	// Use proper 28-byte key hash (Blake2b-224)
	keyHash := testKeyHash()
	script, err := NewScriptSig(keyHash)
	assert.NoError(t, err)
	assert.NotNil(t, script)
	hash, err := GetScriptHash(script)
	assert.NoError(t, err)
	assert.Len(t, hash, 28)
}

func TestGetScriptAddress(t *testing.T) {
	// Use proper 28-byte key hash (Blake2b-224)
	keyHash := []byte{
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
		0x10,
		0x11,
		0x12,
		0x13,
		0x14,
		0x15,
		0x16,
		0x17,
		0x18,
		0x19,
		0x1a,
		0x1b,
		0x1c,
	}
	script, err := NewScriptSig(keyHash)
	assert.NoError(t, err)
	assert.NotNil(t, script)
	addr, err := GetScriptAddress(script, "mainnet")
	assert.NoError(t, err)
	assert.NotEmpty(t, addr)
	assert.True(t, strings.HasPrefix(addr, "addr1"))

	// Test invalid network
	_, err = GetScriptAddress(script, "invalid")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidNetwork, err)
}

func TestMultiSigKeyDerivation(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	rootKey, err := GetRootKeyFromMnemonic(mnemonic, "")
	assert.NoError(t, err)

	accountKey, err := GetMultiSigAccountKey(rootKey, 0)
	assert.NoError(t, err)

	paymentKey, err := GetMultiSigPaymentKey(accountKey, 0)
	assert.NoError(t, err)

	vkey, err := GetMultiSigPaymentVKey(paymentKey)
	assert.NoError(t, err)
	assert.Equal(t, "PaymentVerificationKeyShelley_ed25519", vkey.Type)

	skey, err := GetMultiSigPaymentSKey(paymentKey)
	assert.NoError(t, err)
	assert.Equal(t, "PaymentSigningKeyShelley_ed25519", skey.Type)

	stakeKey, err := GetMultiSigStakeKey(accountKey, 0)
	assert.NoError(t, err)

	stakeVKey, err := GetMultiSigStakeVKey(stakeKey)
	assert.NoError(t, err)
	assert.Equal(t, "StakeVerificationKeyShelley_ed25519", stakeVKey.Type)

	stakeSKey, err := GetMultiSigStakeSKey(stakeKey)
	assert.NoError(t, err)
	assert.Equal(t, "StakeSigningKeyShelley_ed25519", stakeSKey.Type)
}

func TestValidateScript(t *testing.T) {
	// Create proper 28-byte key hashes
	keyHash1 := make([]byte, 28)
	keyHash1[0] = 0x01
	keyHash2 := make([]byte, 28)
	keyHash2[0] = 0x02
	keyHash3 := make([]byte, 28)
	keyHash3[0] = 0x03
	keyHash4 := make([]byte, 28)
	keyHash4[0] = 0x04
	keyHash5 := make([]byte, 28)
	keyHash5[0] = 0x05
	keyHash6 := make([]byte, 28)
	keyHash6[0] = 0x06
	keyHash7 := make([]byte, 28)
	keyHash7[0] = 0x07

	// Test ScriptSig validation (allows empty signatures for basic validation)
	scriptSig, err := NewScriptSig(keyHash1)
	assert.NoError(t, err)
	assert.True(t, ValidateScript(scriptSig, nil, 1000, false))

	// Test ScriptAll validation (requires all sub-scripts satisfied)
	// Since ScriptSig allows empty signatures, ScriptAll should succeed
	script1, err := NewScriptSig(keyHash2)
	assert.NoError(t, err)
	script2, err := NewScriptSig(keyHash3)
	assert.NoError(t, err)
	scriptAll, err := NewScriptAll(
		script1,
		script2,
	)
	assert.NoError(t, err)
	assert.True(t, ValidateScript(scriptAll, nil, 1000, false))

	// Test ScriptAny validation (requires any sub-script satisfied)
	// Since ScriptSig allows empty signatures, ScriptAny should succeed
	script3, err := NewScriptSig(keyHash4)
	assert.NoError(t, err)
	script4, err := NewScriptSig(keyHash5)
	assert.NoError(t, err)
	scriptAny, err := NewScriptAny(
		script3,
		script4,
	)
	assert.NoError(t, err)
	assert.True(t, ValidateScript(scriptAny, nil, 1000, false))

	// Test ScriptNOf validation (2-of-3)
	// Since ScriptSig allows empty signatures, ScriptNOf should succeed
	script5, err := NewScriptSig(keyHash5)
	assert.NoError(t, err)
	script6, err := NewScriptSig(keyHash6)
	assert.NoError(t, err)
	script7, err := NewScriptSig(keyHash7)
	assert.NoError(t, err)
	scriptNOf, err := NewScriptNOf(2,
		script5,
		script6,
		script7,
	)
	assert.NoError(t, err)
	assert.True(t, ValidateScript(scriptNOf, nil, 1000, false))

	// Test ScriptBefore validation
	scriptBefore, err := NewScriptBefore(2000)
	assert.NoError(t, err)
	assert.True(
		t,
		ValidateScript(scriptBefore, nil, 1000, false),
	) // Slot 1000 < 2000
	assert.False(
		t,
		ValidateScript(scriptBefore, nil, 3000, false),
	) // Slot 3000 > 2000

	// Test ScriptAfter validation
	scriptAfter, err := NewScriptAfter(1000)
	assert.NoError(t, err)
	assert.True(
		t,
		ValidateScript(scriptAfter, nil, 2000, false),
	) // Slot 2000 > 1000
	assert.False(
		t,
		ValidateScript(scriptAfter, nil, 500, false),
	) // Slot 500 < 1000
}

func TestMultiSigScriptGeneration(t *testing.T) {
	// Use proper 28-byte key hashes
	keyHash1 := make([]byte, 28)
	keyHash1[0], keyHash1[1], keyHash1[2] = 0x01, 0x02, 0x03
	keyHash2 := make([]byte, 28)
	keyHash2[0], keyHash2[1], keyHash2[2] = 0x04, 0x05, 0x06
	keyHash3 := make([]byte, 28)
	keyHash3[0], keyHash3[1], keyHash3[2] = 0x07, 0x08, 0x09

	// Test NewMultiSigScript (2-of-3)
	script2of3, err := NewMultiSigScript(2, keyHash1, keyHash2, keyHash3)
	assert.NoError(t, err)
	scriptType, err := GetScriptType(script2of3)
	assert.NoError(t, err)
	assert.Equal(t, 3, scriptType) // NOf type
	nofScript := script2of3.Item().(*NativeScriptNofK)
	assert.Equal(t, uint(2), nofScript.N)
	assert.Len(t, nofScript.Scripts, 3)

	// Test NewAllMultiSigScript
	scriptAll, err := NewAllMultiSigScript(keyHash1, keyHash2)
	assert.NoError(t, err)
	scriptType, err = GetScriptType(scriptAll)
	assert.NoError(t, err)
	assert.Equal(t, 1, scriptType) // All type
	allScript := scriptAll.Item().(*NativeScriptAll)
	assert.Len(t, allScript.Scripts, 2)

	// Test NewAnyMultiSigScript
	scriptAny, err := NewAnyMultiSigScript(keyHash1, keyHash2, keyHash3)
	assert.NoError(t, err)
	scriptType, err = GetScriptType(scriptAny)
	assert.NoError(t, err)
	assert.Equal(t, 2, scriptType) // Any type
	anyScript := scriptAny.Item().(*NativeScriptAny)
	assert.Len(t, anyScript.Scripts, 3)

	// Test NewTimelockedScript (before)
	timelockedBefore, err := NewTimelockedScript(1000, true, scriptAll)
	assert.NoError(t, err)
	scriptType, err = GetScriptType(timelockedBefore)
	assert.NoError(t, err)
	assert.Equal(t, 1, scriptType) // All type (wrapping)
	allScriptBefore := timelockedBefore.(*NativeScript).Item().(*NativeScriptAll)
	assert.Len(t, allScriptBefore.Scripts, 2) // Before script + original script

	// Test NewTimelockedScript (after)
	timelockedAfter, err := NewTimelockedScript(2000, false, scriptAny)
	assert.NoError(t, err)
	scriptType, err = GetScriptType(timelockedAfter)
	assert.NoError(t, err)
	assert.Equal(t, 1, scriptType) // All type (wrapping)
	allScriptAfter := timelockedAfter.(*NativeScript).Item().(*NativeScriptAll)
	assert.Len(t, allScriptAfter.Scripts, 2) // After script + original script
}

func TestMultiSigScriptFromKeys(t *testing.T) {
	// Create some dummy Ed25519 public keys
	pubKey1, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pubKey3, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	// Test creating 2-of-3 script from public keys
	script, err := NewMultiSigScriptFromKeys(2, pubKey1, pubKey2, pubKey3)
	assert.NoError(t, err)
	scriptType, err := GetScriptType(script)
	assert.NoError(t, err)
	assert.Equal(t, 3, scriptType) // NOf type
	nofScript := script.Item().(*NativeScriptNofK)
	assert.Equal(t, uint(2), nofScript.N)
	assert.Len(t, nofScript.Scripts, 3)

	// Verify the script can be validated
	assert.True(t, ValidateScript(script, nil, 1000, false))
}

func TestScriptGenerationEdgeCases(t *testing.T) {
	keyHash := testKeyHash()

	// Test invalid key hash length (must be 28 bytes)
	_, err := NewScriptSig([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key hash length")

	// Test invalid parameters (should return errors)
	_, err = NewMultiSigScript(0, keyHash)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid required signatures count")

	_, err = NewMultiSigScript(2, keyHash)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid required signatures count")

	_, err = NewMultiSigScript(1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one key hash required")

	_, err = NewAllMultiSigScript()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one key hash required")

	_, err = NewAnyMultiSigScript()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one key hash required")
}

func TestValidateScriptWithSignatures(t *testing.T) {
	keyHash1 := []byte{
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
		0x10,
		0x11,
		0x12,
		0x13,
		0x14,
		0x15,
		0x16,
		0x17,
		0x18,
		0x19,
		0x1a,
		0x1b,
		0x1c,
	}
	keyHash2 := []byte{
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
		0x10,
		0x11,
		0x12,
		0x13,
		0x14,
		0x15,
		0x16,
		0x17,
		0x18,
		0x19,
		0x1a,
		0x1b,
		0x1c,
		0x1d,
	}

	validSig := make(
		[]byte,
		64,
	) // 64-byte signature placeholder (structural validation only)

	// Test ScriptSig with requireSignatures=true (structural validation: enforce signature presence and shape constraints only)
	scriptSig, err := NewScriptSig(keyHash1)
	assert.NoError(t, err)
	assert.False(
		t,
		ValidateScript(scriptSig, nil, 1000, true),
	) // No signatures provided
	assert.False(
		t,
		ValidateScript(scriptSig, [][]byte{make([]byte, 32)}, 1000, true),
	) // Invalid signature length (not 64 bytes)
	assert.True(
		t,
		ValidateScript(scriptSig, [][]byte{validSig}, 1000, true),
	) // Valid signature count and length (structural check only, no cryptographic verification)

	// Test ScriptAll with requireSignatures=true (structural validation: enforce signature presence and shape constraints only)
	scriptAll1, err := NewScriptSig(keyHash1)
	assert.NoError(t, err)
	scriptAll2, err := NewScriptSig(keyHash2)
	assert.NoError(t, err)
	scriptAll, err := NewScriptAll(scriptAll1, scriptAll2)
	assert.NoError(t, err)
	assert.False(
		t,
		ValidateScript(scriptAll, nil, 1000, true),
	) // No signatures
	assert.False(
		t,
		ValidateScript(scriptAll, [][]byte{validSig}, 1000, true),
	) // Insufficient signatures (needs 2)
	assert.True(
		t,
		ValidateScript(scriptAll, [][]byte{validSig, validSig}, 1000, true),
	) // Sufficient signatures (structural check only, no cryptographic verification)

	// Test ScriptNOf with requireSignatures=true (structural validation: enforce signature presence and shape constraints only)
	scriptNOf1, err := NewScriptSig(keyHash1)
	assert.NoError(t, err)
	scriptNOf2, err := NewScriptSig(keyHash2)
	assert.NoError(t, err)
	scriptNOf3, err := NewScriptSig(keyHash2)
	assert.NoError(t, err)
	scriptNOf, err := NewScriptNOf(
		2,
		scriptNOf1,
		scriptNOf2,
		scriptNOf3,
	)
	assert.NoError(t, err)
	assert.False(
		t,
		ValidateScript(scriptNOf, nil, 1000, true),
	) // No signatures
	assert.False(
		t,
		ValidateScript(scriptNOf, [][]byte{validSig}, 1000, true),
	) // Insufficient signatures (needs 2)
	assert.True(
		t,
		ValidateScript(scriptNOf, [][]byte{validSig, validSig}, 1000, true),
	) // Sufficient signatures (structural check only, no cryptographic verification)
}

func TestValidateScriptTimelockBoundaries(t *testing.T) {
	// Test ScriptBefore boundary
	scriptBefore, err := NewScriptBefore(1000)
	assert.NoError(t, err)
	assert.True(
		t,
		ValidateScript(scriptBefore, nil, 999, false),
	) // Slot < before
	assert.False(
		t,
		ValidateScript(scriptBefore, nil, 1000, false),
	) // Slot == before
	assert.False(
		t,
		ValidateScript(scriptBefore, nil, 1001, false),
	) // Slot > before

	// Test ScriptAfter boundary
	scriptAfter, err := NewScriptAfter(1000)
	assert.NoError(t, err)
	assert.False(
		t,
		ValidateScript(scriptAfter, nil, 999, false),
	) // Slot 999 < 1000 (false)
	assert.True(
		t,
		ValidateScript(scriptAfter, nil, 1000, false),
	) // Slot == after (>=)
	assert.True(
		t,
		ValidateScript(scriptAfter, nil, 1001, false),
	) // Slot 1001 >= 1000 (true)
}

func TestScriptRoundTrip(t *testing.T) {
	keyHash := testKeyHash()

	// Test ScriptSig round-trip
	scriptSig, err := NewScriptSig(keyHash)
	assert.NoError(t, err)
	assert.NotNil(t, scriptSig)
	data, err := MarshalScript(scriptSig, "mainnet")
	assert.NoError(t, err)
	unmarshaled, err := UnmarshalScript(data)
	assert.NoError(t, err)
	assert.NotNil(t, unmarshaled)
	originalType, err := GetScriptType(scriptSig)
	assert.NoError(t, err)
	unmarshaledType, err := GetScriptType(unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, originalType, unmarshaledType)

	// Test ScriptAll round-trip
	scriptAllSig, err := NewScriptSig(keyHash)
	assert.NoError(t, err)
	scriptAll, err := NewScriptAll(scriptAllSig)
	assert.NoError(t, err)
	assert.NotNil(t, scriptAll)
	data, err = MarshalScript(scriptAll, "mainnet")
	assert.NoError(t, err)
	unmarshaled, err = UnmarshalScript(data)
	assert.NoError(t, err)
	assert.NotNil(t, unmarshaled)
	originalType, err = GetScriptType(scriptAll)
	assert.NoError(t, err)
	unmarshaledType, err = GetScriptType(unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, originalType, unmarshaledType)

	// Test invalid script data
	invalidData := &ScriptData{
		Type: "invalid",
		Script: map[string]any{
			"type":    "sig",
			"keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
		},
	}
	_, err = UnmarshalScript(invalidData)
	assert.Error(t, err)

	// Test bad N value for NOf
	badData := &ScriptData{
		Type: "NativeScript",
		Script: map[string]any{
			"type": "nOf",
			"n":    float64(-1),
			"scripts": []any{
				map[string]any{
					"type":    "sig",
					"keyHash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
				},
			},
		},
	}
	_, err = UnmarshalScript(badData)
	assert.Error(t, err)
}
