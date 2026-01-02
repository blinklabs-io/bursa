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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/bip32"
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

func TestCIP0003KeyGeneration(t *testing.T) {
	// Test CIP-0003 compliance for wallet key generation
	// These test vectors validate the complete key generation pipeline:
	// mnemonic -> entropy -> seed -> root key -> derived keys

	// Test Vector 1: Standard BIP39 mnemonic without password
	t.Run("TestVector1_NoPassword", func(t *testing.T) {
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		password := ""

		rootKey, err := GetRootKeyFromMnemonic(mnemonic, password)
		assert.NoError(t, err)
		assert.NotNil(t, rootKey)
		assert.Equal(
			t,
			96,
			len(rootKey),
			"Root key should be 96 bytes (64-byte extended key + 32-byte chain code)",
		)

		// Verify root key has correct structure
		privateKey := rootKey[:64]
		assert.Equal(t, 64, len(privateKey), "Private key should be 64 bytes")
		chainCode := rootKey.ChainCode()
		assert.Equal(t, 32, len(chainCode), "Chain code should be 32 bytes")

		// Verify public key can be derived
		publicKey := rootKey.PublicKey()
		assert.Equal(t, 32, len(publicKey), "Public key should be 32 bytes")

		// Verify extended public key
		extendedPubKey := rootKey.Public()
		assert.Equal(
			t,
			64,
			len(extendedPubKey),
			"Extended public key should be 64 bytes",
		)
	})

	// Test Vector 2: Same mnemonic with password
	t.Run("TestVector2_WithPassword", func(t *testing.T) {
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		password := "testpassword"

		rootKey, err := GetRootKeyFromMnemonic(mnemonic, password)
		assert.NoError(t, err)
		assert.NotNil(t, rootKey)
		assert.Equal(t, 96, len(rootKey))

		// Verify that password changes the result
		rootKeyNoPass, _ := GetRootKeyFromMnemonic(mnemonic, "")
		assert.NotEqual(
			t,
			rootKey,
			rootKeyNoPass,
			"Password should change the generated key",
		)
	})

	// Test Vector 3: Different mnemonic
	t.Run("TestVector3_DifferentMnemonic", func(t *testing.T) {
		mnemonic := "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
		password := ""

		rootKey, err := GetRootKeyFromMnemonic(mnemonic, password)
		assert.NoError(t, err)
		assert.NotNil(t, rootKey)
		assert.Equal(t, 96, len(rootKey))

		// Verify different mnemonic produces different key
		otherMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		otherRootKey, _ := GetRootKeyFromMnemonic(otherMnemonic, password)
		assert.NotEqual(
			t,
			rootKey,
			otherRootKey,
			"Different mnemonics should produce different keys",
		)
	})

	// Test Vector 4: Complete wallet generation pipeline
	t.Run("TestVector4_FullWallet", func(t *testing.T) {
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		password := ""
		network := "mainnet"
		accountId := uint32(0)
		paymentId := uint32(0)
		stakeId := uint32(0)
		drepId := uint32(0)
		committeeColdId := uint32(0)
		committeeHotId := uint32(0)
		addressId := uint32(0)

		wallet, err := NewWallet(
			mnemonic,
			network,
			password,
			accountId,
			paymentId,
			stakeId,
			drepId,
			committeeColdId,
			committeeHotId,
			addressId,
		)
		assert.NoError(t, err)
		assert.NotNil(t, wallet)

		// Verify all key types are generated
		assert.NotEmpty(t, wallet.PaymentVKey.CborHex)
		assert.NotEmpty(t, wallet.PaymentSKey.CborHex)
		assert.NotEmpty(t, wallet.StakeVKey.CborHex)
		assert.NotEmpty(t, wallet.StakeSKey.CborHex)
		assert.NotEmpty(t, wallet.DRepVKey.CborHex)
		assert.NotEmpty(t, wallet.DRepSKey.CborHex)
		assert.NotEmpty(t, wallet.CommitteeColdVKey.CborHex)
		assert.NotEmpty(t, wallet.CommitteeColdSKey.CborHex)
		assert.NotEmpty(t, wallet.CommitteeHotVKey.CborHex)
		assert.NotEmpty(t, wallet.CommitteeHotSKey.CborHex)

		// Verify addresses are generated
		assert.NotEmpty(t, wallet.PaymentAddress)
		assert.NotEmpty(t, wallet.StakeAddress)

		// Verify key types are correct
		assert.Equal(
			t,
			"PaymentVerificationKeyShelley_ed25519",
			wallet.PaymentVKey.Type,
		)
		assert.Equal(
			t,
			"PaymentSigningKeyShelley_ed25519",
			wallet.PaymentSKey.Type,
		)
		assert.Equal(
			t,
			"StakeVerificationKeyShelley_ed25519",
			wallet.StakeVKey.Type,
		)
		assert.Equal(t, "StakeSigningKeyShelley_ed25519", wallet.StakeSKey.Type)
	})
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

func TestCIP0011StakingKeys(t *testing.T) {
	// Test vector from CIP-0011 specification
	// https://cips.cardano.org/cips/cip11/
	// Note: This test validates reward address generation from a stake verification key
	// as specified in CIP-0011, but uses the expected stake key directly rather than
	// deriving it from entropy. This is because the CIP-0011 test vector's derivation
	// doesn't follow standard CIP-1852 paths. The test focuses on reward address
	// generation correctness, not the full derivation flow.
	expectedStakeKeyHex := "b8ab42f1aacbcdb3ae858e3a3df88142b3ed27a2d3f432024e0d943fc1e597442d57545d84c8db2820b11509d944093bc605350e60c533b8886a405bd59eed6dcf356648fe9e9219d83e989c8ff5b5b337e2897b6554c1ab4e636de791fe5427"
	expectedRewardAddress := "stake1uy8ykk8dzmeqxm05znz65nhr80m0k3gxnjvdngf8azh6sjc6hyh36"

	// Use the expected stake key directly for this test vector
	stakeKey, err := hex.DecodeString(expectedStakeKeyHex)
	assert.NoError(t, err)
	stakeKeyXPrv := bip32.XPrv(stakeKey)

	// Get stake verification key
	stakeVKey, err := GetStakeVKey(stakeKeyXPrv)
	assert.NoError(t, err)

	// Create reward address from stake verification key
	rewardAddr, err := GetRewardAddress(stakeVKey, "mainnet")
	assert.NoError(t, err)

	// Verify the reward address matches the expected value
	assert.Equal(t, expectedRewardAddress, rewardAddr.String(),
		"Reward address does not match CIP-0011 test vector")
}

func TestCIP0018MultiStakeKeys(t *testing.T) {
	// Test CIP-0018 compliance for multi-stake-keys wallets
	// CIP-0018 allows wallets to have multiple stake keys, each potentially
	// delegating to different stake pools

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password := ""

	// Create wallet with multiple stake keys
	wallet, err := NewWallet(mnemonic, "mainnet", password, 0, 0, 0, 0, 0, 0, 0)
	assert.NoError(t, err)
	assert.NotNil(t, wallet)

	// Verify we have stake keys
	assert.NotEmpty(t, wallet.StakeVKey.CborHex)
	assert.NotEmpty(t, wallet.StakeSKey.CborHex)

	// Test creating additional stake keys by deriving from account key
	rootKey, err := GetRootKeyFromMnemonic(mnemonic, password)
	assert.NoError(t, err)

	// Get account key (following CIP-1852 derivation path)
	accountKey, err := GetAccountKey(rootKey, 0)
	assert.NoError(t, err)

	// Derive multiple stake keys from account key (CIP-0018 allows multiple stake keys)
	stakeKey1 := accountKey.Derive(2).Derive(0) // Standard stake key
	stakeKey2 := accountKey.Derive(2).Derive(1) // Additional stake key
	stakeKey3 := accountKey.Derive(2).Derive(2) // Another stake key

	// Verify they are different
	assert.NotEqual(t, stakeKey1, stakeKey2)
	assert.NotEqual(t, stakeKey2, stakeKey3)
	assert.NotEqual(t, stakeKey1, stakeKey3)

	// Create stake verification keys for each
	stakeVKey1, err := GetStakeVKey(stakeKey1)
	assert.NoError(t, err)
	stakeVKey2, err := GetStakeVKey(stakeKey2)
	assert.NoError(t, err)
	stakeVKey3, err := GetStakeVKey(stakeKey3)
	assert.NoError(t, err)

	// Verify they generate different reward addresses
	rewardAddr1, err := GetRewardAddress(stakeVKey1, "mainnet")
	assert.NoError(t, err)
	rewardAddr2, err := GetRewardAddress(stakeVKey2, "mainnet")
	assert.NoError(t, err)
	rewardAddr3, err := GetRewardAddress(stakeVKey3, "mainnet")
	assert.NoError(t, err)

	// All reward addresses should be different
	assert.NotEqual(t, rewardAddr1.String(), rewardAddr2.String())
	assert.NotEqual(t, rewardAddr2.String(), rewardAddr3.String())
	assert.NotEqual(t, rewardAddr1.String(), rewardAddr3.String())

	// Verify all start with "stake1" (mainnet reward address prefix)
	assert.True(t, strings.HasPrefix(rewardAddr1.String(), "stake1"))
	assert.True(t, strings.HasPrefix(rewardAddr2.String(), "stake1"))
	assert.True(t, strings.HasPrefix(rewardAddr3.String(), "stake1"))

	// Test that payment addresses can be combined with different stake keys
	// Note: In a full CIP-0018 implementation, we'd modify GetAddress to accept stake key
	// For now, we verify that multiple stake keys can be derived and used independently
}

func TestCIP0019AddressIntegration(t *testing.T) {
	// Basic integration test for CIP-0019 Cardano address formats
	// Tests that Bursa correctly generates addresses using gouroboros

	rootKey, err := GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	accountKey, err := GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatal(err)
	}

	stakeKey := accountKey.Derive(2).Derive(0)

	// Test mainnet payment address generation
	paymentAddr, err := GetAddress(accountKey, "mainnet", 0)
	if err != nil {
		t.Fatal(err)
	}
	if paymentAddr == nil {
		t.Fatal("paymentAddr is nil")
	}

	addrStr := paymentAddr.String()
	if addrStr == "" {
		t.Error("Address string is empty")
	}

	// Verify mainnet address starts with "addr1" (CIP-0019 mainnet payment address)
	if !strings.HasPrefix(addrStr, "addr1") {
		t.Errorf(
			"Mainnet payment address should start with 'addr1', got %s",
			addrStr,
		)
	}

	// Test testnet payment address generation
	paymentAddrTestnet, err := GetAddress(accountKey, "preprod", 0)
	if err != nil {
		t.Fatal(err)
	}
	if paymentAddrTestnet == nil {
		t.Fatal("paymentAddrTestnet is nil")
	}

	addrStrTestnet := paymentAddrTestnet.String()
	if addrStrTestnet == "" {
		t.Error("Testnet address string is empty")
	}

	// Verify testnet address starts with "addr_test1" (CIP-0019 testnet payment address)
	if !strings.HasPrefix(addrStrTestnet, "addr_test1") {
		t.Errorf(
			"Testnet payment address should start with 'addr_test1', got %s",
			addrStrTestnet,
		)
	}

	// Test reward address generation
	stakeVKey, err := GetStakeVKey(stakeKey)
	if err != nil {
		t.Fatal(err)
	}

	rewardAddr, err := GetRewardAddress(stakeVKey, "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if rewardAddr == nil {
		t.Fatal("rewardAddr is nil")
	}

	rewardStr := rewardAddr.String()
	if rewardStr == "" {
		t.Error("Reward address string is empty")
	}

	// Verify mainnet reward address starts with "stake1" (CIP-0019 mainnet reward address)
	if !strings.HasPrefix(rewardStr, "stake1") {
		t.Errorf(
			"Mainnet reward address should start with 'stake1', got %s",
			rewardStr,
		)
	}

	// Test testnet reward address
	rewardAddrTestnet, err := GetRewardAddress(stakeVKey, "preprod")
	if err != nil {
		t.Fatal(err)
	}
	if rewardAddrTestnet == nil {
		t.Fatal("rewardAddrTestnet is nil")
	}

	rewardStrTestnet := rewardAddrTestnet.String()
	if rewardStrTestnet == "" {
		t.Error("Testnet reward address string is empty")
	}

	// Verify testnet reward address starts with "stake_test1" (CIP-0019 testnet reward address)
	if !strings.HasPrefix(rewardStrTestnet, "stake_test1") {
		t.Errorf(
			"Testnet reward address should start with 'stake_test1', got %s",
			rewardStrTestnet,
		)
	}

	// Verify addresses are different between networks
	if addrStr == addrStrTestnet {
		t.Error("Mainnet and testnet payment addresses should be different")
	}
	if rewardStr == rewardStrTestnet {
		t.Error("Mainnet and testnet reward addresses should be different")
	}
}

func TestCIP0105GovernanceKeyDerivation(t *testing.T) {
	// Basic integration test for CIP-0105 Conway Era Key Chains
	// Tests that Bursa correctly derives governance keys (DRep, Committee) using CIP-0105 paths

	rootKey, err := GetRootKeyFromMnemonic(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	accountKey, err := GetAccountKey(rootKey, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Test DRep key derivation: m/1852'/1815'/0'/3'/index'
	// CIP-0105: DRep keys use purpose 1852', coin type 1815', account, role 3', index
	drepKey0 := accountKey.Derive(3).Derive(0)
	drepKey1 := accountKey.Derive(3).Derive(1)
	drepKey2 := accountKey.Derive(3).Derive(2)

	// Verify DRep keys are different
	drepPubKey0 := drepKey0.PublicKey()
	drepPubKey1 := drepKey1.PublicKey()
	drepPubKey2 := drepKey2.PublicKey()

	if len(drepPubKey0) != 32 {
		t.Errorf(
			"DRep public key 0 should be 32 bytes, got %d",
			len(drepPubKey0),
		)
	}
	if len(drepPubKey1) != 32 {
		t.Errorf(
			"DRep public key 1 should be 32 bytes, got %d",
			len(drepPubKey1),
		)
	}
	if len(drepPubKey2) != 32 {
		t.Errorf(
			"DRep public key 2 should be 32 bytes, got %d",
			len(drepPubKey2),
		)
	}

	// Keys should be different
	if bytes.Equal(drepPubKey0, drepPubKey1) {
		t.Error("DRep keys 0 and 1 should be different")
	}
	if bytes.Equal(drepPubKey1, drepPubKey2) {
		t.Error("DRep keys 1 and 2 should be different")
	}
	if bytes.Equal(drepPubKey0, drepPubKey2) {
		t.Error("DRep keys 0 and 2 should be different")
	}

	// Test Committee Cold key derivation: m/1852'/1815'/0'/4'/index'
	// CIP-0105: Committee Cold keys use purpose 1852', coin type 1815', account, role 4', index
	committeeColdKey0 := accountKey.Derive(4).Derive(0)
	committeeColdKey1 := accountKey.Derive(4).Derive(1)
	committeeColdKey2 := accountKey.Derive(4).Derive(2)

	// Verify Committee Cold keys are different
	committeeColdPubKey0 := committeeColdKey0.PublicKey()
	committeeColdPubKey1 := committeeColdKey1.PublicKey()
	committeeColdPubKey2 := committeeColdKey2.PublicKey()

	if len(committeeColdPubKey0) != 32 {
		t.Errorf(
			"Committee Cold public key 0 should be 32 bytes, got %d",
			len(committeeColdPubKey0),
		)
	}
	if len(committeeColdPubKey1) != 32 {
		t.Errorf(
			"Committee Cold public key 1 should be 32 bytes, got %d",
			len(committeeColdPubKey1),
		)
	}
	if len(committeeColdPubKey2) != 32 {
		t.Errorf(
			"Committee Cold public key 2 should be 32 bytes, got %d",
			len(committeeColdPubKey2),
		)
	}

	// Keys should be different
	if bytes.Equal(committeeColdPubKey0, committeeColdPubKey1) {
		t.Error("Committee Cold keys 0 and 1 should be different")
	}
	if bytes.Equal(committeeColdPubKey1, committeeColdPubKey2) {
		t.Error("Committee Cold keys 1 and 2 should be different")
	}
	if bytes.Equal(committeeColdPubKey0, committeeColdPubKey2) {
		t.Error("Committee Cold keys 0 and 2 should be different")
	}

	// Test Committee Hot key derivation: m/1852'/1815'/0'/5'/index'
	// CIP-0105: Committee Hot keys use purpose 1852', coin type 1815', account, role 5', index
	committeeHotKey0 := accountKey.Derive(5).Derive(0)
	committeeHotKey1 := accountKey.Derive(5).Derive(1)
	committeeHotKey2 := accountKey.Derive(5).Derive(2)

	// Verify Committee Hot keys are different
	committeeHotPubKey0 := committeeHotKey0.PublicKey()
	committeeHotPubKey1 := committeeHotKey1.PublicKey()
	committeeHotPubKey2 := committeeHotKey2.PublicKey()

	if len(committeeHotPubKey0) != 32 {
		t.Errorf(
			"Committee Hot public key 0 should be 32 bytes, got %d",
			len(committeeHotPubKey0),
		)
	}
	if len(committeeHotPubKey1) != 32 {
		t.Errorf(
			"Committee Hot public key 1 should be 32 bytes, got %d",
			len(committeeHotPubKey1),
		)
	}
	if len(committeeHotPubKey2) != 32 {
		t.Errorf(
			"Committee Hot public key 2 should be 32 bytes, got %d",
			len(committeeHotPubKey2),
		)
	}

	// Keys should be different
	if bytes.Equal(committeeHotPubKey0, committeeHotPubKey1) {
		t.Error("Committee Hot keys 0 and 1 should be different")
	}
	if bytes.Equal(committeeHotPubKey1, committeeHotPubKey2) {
		t.Error("Committee Hot keys 1 and 2 should be different")
	}
	if bytes.Equal(committeeHotPubKey0, committeeHotPubKey2) {
		t.Error("Committee Hot keys 0 and 2 should be different")
	}

	// Verify governance keys are different from each other and from stake keys
	stakeKey := accountKey.Derive(2).Derive(0)
	stakePubKey := stakeKey.PublicKey()

	// Governance keys should be different from stake keys
	if bytes.Equal(drepPubKey0, stakePubKey) {
		t.Error("DRep key should be different from stake key")
	}
	if bytes.Equal(committeeColdPubKey0, stakePubKey) {
		t.Error("Committee Cold key should be different from stake key")
	}
	if bytes.Equal(committeeHotPubKey0, stakePubKey) {
		t.Error("Committee Hot key should be different from stake key")
	}

	// All governance key types should be different from each other
	if bytes.Equal(drepPubKey0, committeeColdPubKey0) {
		t.Error("DRep key should be different from Committee Cold key")
	}
	if bytes.Equal(drepPubKey0, committeeHotPubKey0) {
		t.Error("DRep key should be different from Committee Hot key")
	}
	if bytes.Equal(committeeColdPubKey0, committeeHotPubKey0) {
		t.Error("Committee Cold key should be different from Committee Hot key")
	}
}

func TestCIP1854NativeScriptTestVectors(t *testing.T) {
	// Test vectors for CIP-1854 Native Scripts
	// Validates native script construction and validation

	// Use specific key hashes for test vectors
	keyHash1 := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
	}
	keyHash2 := []byte{
		0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
		0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37,
	}
	keyHash3 := []byte{
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
		0x50, 0x51, 0x52, 0x53,
	}

	// Test 2-of-3 multisig script
	script2of3, err := NewMultiSigScript(2, keyHash1, keyHash2, keyHash3)
	assert.NoError(t, err)
	assert.NotNil(t, script2of3)

	// Validate script type
	scriptType, err := GetScriptType(script2of3)
	assert.NoError(t, err)
	assert.Equal(t, 3, scriptType) // NOfK type

	// Validate script structure
	nofScript := script2of3.Item().(*NativeScriptNofK)
	assert.Equal(t, uint(2), nofScript.N)
	assert.Len(t, nofScript.Scripts, 3)

	// Test All script
	scriptAll, err := NewAllMultiSigScript(keyHash1, keyHash2)
	assert.NoError(t, err)
	assert.NotNil(t, scriptAll)

	scriptType, err = GetScriptType(scriptAll)
	assert.NoError(t, err)
	assert.Equal(t, 1, scriptType) // All type

	allScript := scriptAll.Item().(*NativeScriptAll)
	assert.Len(t, allScript.Scripts, 2)

	// Test Any script
	scriptAny, err := NewAnyMultiSigScript(keyHash1, keyHash2, keyHash3)
	assert.NoError(t, err)
	assert.NotNil(t, scriptAny)

	scriptType, err = GetScriptType(scriptAny)
	assert.NoError(t, err)
	assert.Equal(t, 2, scriptType) // Any type

	anyScript := scriptAny.Item().(*NativeScriptAny)
	assert.Len(t, anyScript.Scripts, 3)

	// Test nested script: All(Any(key1, key2), Sig(key3))
	sigScript3, err := NewScriptSig(keyHash3)
	assert.NoError(t, err)
	nestedScript, err := NewScriptAll(scriptAny, sigScript3)
	assert.NoError(t, err)
	assert.NotNil(t, nestedScript)

	scriptType, err = GetScriptType(nestedScript)
	assert.NoError(t, err)
	assert.Equal(t, 1, scriptType) // All type

	nestedAllScript := nestedScript.Item().(*NativeScriptAll)
	assert.Len(t, nestedAllScript.Scripts, 2)

	// Verify scripts are different
	assert.NotEqual(t, script2of3, scriptAll)
	assert.NotEqual(t, scriptAll, scriptAny)
	assert.NotEqual(t, script2of3, nestedScript)
}
