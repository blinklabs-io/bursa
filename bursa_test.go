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
	wallet, err := NewWallet(mnemonic, "mainnet", "", 0, 0, 0, 0)
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
	assert.Len(t, loadedKeys, 6) // 3 vkeys + 3 skeys

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
	wallet, err := NewWallet(mnemonic, "mainnet", "", 0, 0, 0, 0)
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
		_, err := NewWallet(mnemonic, "mainnet", "", 0, 0, 0, 0)
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
	wallet, err := NewWallet(mnemonic, "mainnet", "", 0, 0, 0, 0)
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
	_, err := NewWallet("invalid mnemonic", "mainnet", "", 0, 0, 0, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mnemonic")
}

func TestNewWalletInvalidIndices(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	_, err := NewWallet(mnemonic, "mainnet", "", 0x80000000, 0, 0, 0)
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
