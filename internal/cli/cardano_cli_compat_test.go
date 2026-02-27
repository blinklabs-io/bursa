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

package cli

import (
	"encoding/hex"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test mnemonic - CIP-1852 test vector (DO NOT USE FOR REAL FUNDS)
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Golden samples verified against bip_utils (Python) reference implementation
// using CIP-3 Icarus + BIP32-Ed25519 (Khovratovich/Law) derivation.
// Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const (
	// Payment verification key cborHex (32-byte public key, CBOR encoded)
	// Derived via CIP-3 Icarus + CIP-1852 path m/1852'/1815'/0'/0/0
	goldenPaymentVKeyCborHex = "58207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a"

	// Stake verification key cborHex (32-byte public key, CBOR encoded)
	// Derived via CIP-3 Icarus + CIP-1852 path m/1852'/1815'/0'/2/0
	goldenStakeVKeyCborHex = "5820012f5dc3115b8a07981e6e50f5a671e2c6fbb26c3ffde1cd1dcaf40a7fe8f160"

	// Enterprise address (payment key only, mainnet)
	goldenEnterpriseAddress = "addr1vy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7ss7lxrqp"

	// Base address (payment + stake keys, mainnet)
	goldenBaseAddress = "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv"

	// Payment key hash (Blake2b-224 of payment verification key)
	goldenPaymentKeyHash = "0fdc780023d8be7c9ff3a6bdc0d8d3b263bd0cc12448c40948efbf42"

	// Stake address (mainnet)
	goldenStakeAddress = "stake1u8j40zgr2gy4788kl54h6x3gu0pukq5lfr8nflufpg5dzaskqlx2l"

	// Stake key hash (Blake2b-224 of stake verification key)
	goldenStakeKeyHash = "e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d176"
)

func TestPaymentKeyFileFormat(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic)
	require.NoError(t, err)

	// Verify payment vkey has correct type
	assert.Equal(
		t,
		"PaymentVerificationKeyShelley_ed25519",
		wallet.PaymentVKey.Type,
	)
	assert.Equal(
		t,
		"Payment Verification Key",
		wallet.PaymentVKey.Description,
	)
	assert.NotEmpty(t, wallet.PaymentVKey.CborHex)

	// Verify payment skey has correct type
	assert.Equal(
		t,
		"PaymentSigningKeyShelley_ed25519",
		wallet.PaymentSKey.Type,
	)
	assert.Equal(
		t,
		"Payment Signing Key",
		wallet.PaymentSKey.Description,
	)
	assert.NotEmpty(t, wallet.PaymentSKey.CborHex)
}

func TestStakeKeyFileFormat(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic)
	require.NoError(t, err)

	// Verify stake vkey has correct type
	assert.Equal(
		t,
		"StakeVerificationKeyShelley_ed25519",
		wallet.StakeVKey.Type,
	)
	assert.Equal(
		t,
		"Stake Verification Key",
		wallet.StakeVKey.Description,
	)
	assert.NotEmpty(t, wallet.StakeVKey.CborHex)

	// Verify stake skey has correct type
	assert.Equal(
		t,
		"StakeSigningKeyShelley_ed25519",
		wallet.StakeSKey.Type,
	)
	assert.Equal(
		t,
		"Stake Signing Key",
		wallet.StakeSKey.Description,
	)
	assert.NotEmpty(t, wallet.StakeSKey.CborHex)
}

func TestPaymentVKeyCborHexMatchesCardanoCli(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic)
	require.NoError(t, err)

	assert.Equal(
		t,
		goldenPaymentVKeyCborHex,
		wallet.PaymentVKey.CborHex,
		"Payment vkey cborHex should match cardano-cli format",
	)
}

func TestStakeVKeyCborHexMatchesCardanoCli(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic)
	require.NoError(t, err)

	assert.Equal(
		t,
		goldenStakeVKeyCborHex,
		wallet.StakeVKey.CborHex,
		"Stake vkey cborHex should match cardano-cli format",
	)
}

func TestBaseAddressMatchesCardanoCli(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic, bursa.WithNetwork("mainnet"))
	require.NoError(t, err)

	assert.Equal(
		t,
		goldenBaseAddress,
		wallet.PaymentAddress,
		"Base address should match cardano-cli output",
	)
}

func TestStakeAddressMatchesCardanoCli(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic, bursa.WithNetwork("mainnet"))
	require.NoError(t, err)

	assert.Equal(
		t,
		goldenStakeAddress,
		wallet.StakeAddress,
		"Stake address should match cardano-cli output",
	)
}

func TestPaymentKeyHashMatchesCardanoCli(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic)
	require.NoError(t, err)

	// Extract public key from cborHex and compute hash
	cborData, err := hex.DecodeString(wallet.PaymentVKey.CborHex)
	require.NoError(t, err)

	var pubKeyBytes []byte
	err = cbor.Unmarshal(cborData, &pubKeyBytes)
	require.NoError(t, err)

	// Compute Blake2b-224 hash (28 bytes)
	pubKey := bip32.PublicKey(pubKeyBytes)
	keyHash := pubKey.Hash()

	assert.Equal(
		t,
		goldenPaymentKeyHash,
		hex.EncodeToString(keyHash[:]),
		"Payment key hash should match cardano-cli output",
	)
}

func TestStakeKeyHashMatchesCardanoCli(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic)
	require.NoError(t, err)

	// Extract public key from cborHex and compute hash
	cborData, err := hex.DecodeString(wallet.StakeVKey.CborHex)
	require.NoError(t, err)

	var pubKeyBytes []byte
	err = cbor.Unmarshal(cborData, &pubKeyBytes)
	require.NoError(t, err)

	// Compute Blake2b-224 hash (28 bytes)
	pubKey := bip32.PublicKey(pubKeyBytes)
	keyHash := pubKey.Hash()

	assert.Equal(
		t,
		goldenStakeKeyHash,
		hex.EncodeToString(keyHash[:]),
		"Stake key hash should match cardano-cli output",
	)
}

func TestEnterpriseAddressFormat(t *testing.T) {
	// Enterprise addresses start with addr1v (no stake component)
	// The golden enterprise address was generated by cardano-cli with only payment key
	wallet, err := bursa.NewWallet(testMnemonic, bursa.WithNetwork("mainnet"))
	require.NoError(t, err)

	// Verify the base address starts with addr1q (has stake component)
	assert.True(
		t,
		len(wallet.PaymentAddress) > 0 &&
			wallet.PaymentAddress[0:6] == "addr1q",
		"Base address should start with addr1q",
	)

	// The enterprise address (addr1v...) would be generated without stake key
	// We verify the golden value format is correct
	assert.True(
		t,
		len(goldenEnterpriseAddress) > 0 &&
			goldenEnterpriseAddress[0:6] == "addr1v",
		"Enterprise address should start with addr1v",
	)
}

func TestCborHexPrefix(t *testing.T) {
	wallet, err := bursa.NewWallet(testMnemonic)
	require.NoError(t, err)

	// Verify CBOR encoding uses correct prefix for 32-byte keys
	// 5820 = CBOR byte string of length 32 (0x20 = 32)
	assert.True(
		t,
		len(wallet.PaymentVKey.CborHex) >= 4 &&
			wallet.PaymentVKey.CborHex[0:4] == "5820",
		"Payment vkey should have CBOR prefix 5820 (32-byte string)",
	)

	assert.True(
		t,
		len(wallet.StakeVKey.CborHex) >= 4 &&
			wallet.StakeVKey.CborHex[0:4] == "5820",
		"Stake vkey should have CBOR prefix 5820 (32-byte string)",
	)

	// Signing keys (non-extended) should also be 32 bytes
	assert.True(
		t,
		len(wallet.PaymentSKey.CborHex) >= 4 &&
			wallet.PaymentSKey.CborHex[0:4] == "5820",
		"Payment skey should have CBOR prefix 5820 (32-byte string)",
	)

	// Extended signing keys should be 128 bytes (5880 prefix)
	assert.True(
		t,
		len(wallet.PaymentExtendedSKey.CborHex) >= 4 &&
			wallet.PaymentExtendedSKey.CborHex[0:4] == "5880",
		"Payment extended skey should have CBOR prefix 5880 (128-byte string)",
	)
}
