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
