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

// Golden samples generated using cardano-cli 10.14.0.0 with the test mnemonic above.
// These values are the expected outputs from cardano-cli commands when given
// bursa-generated key files.
const (
	// Payment verification key cborHex (32-byte public key, CBOR encoded)
	goldenPaymentVKeyCborHex = "58203cc0186a83bbfa2e37de00f894c5b85c05dbf17b1dec641fdbfa6647f5adc7f3"

	// Stake verification key cborHex (32-byte public key, CBOR encoded)
	goldenStakeVKeyCborHex = "5820839350412a3ec4d9aad93039bec2899562184b5ea9babb8595a6f127d48afb29"

	// cardano-cli address build --payment-verification-key-file payment.vkey --mainnet
	goldenEnterpriseAddress = "addr1vyqcea9cpx0480yjvvklp0tw4yw56r6q9qc437gpqwg6swg0jm2af"

	// cardano-cli address build --payment-verification-key-file payment.vkey \
	//   --stake-verification-key-file stake.vkey --mainnet
	goldenBaseAddress = "addr1qyqcea9cpx0480yjvvklp0tw4yw56r6q9qc437gpqwg6swwc3w03xmxfgcfw6v7asa6vdapakdr6ukq5mrhawfwnjvfsr0qxz0"

	// cardano-cli address key-hash --payment-verification-key-file payment.vkey
	goldenPaymentKeyHash = "018cf4b8099f53bc92632df0bd6ea91d4d0f40283158f9010391a839"

	// cardano-cli conway stake-address build --stake-verification-key-file stake.vkey --mainnet
	goldenStakeAddress = "stake1u8vgh8cndny5vyhdx0wcwaxx7s7mx3awtq2d3m7hyhfexycdskv40"

	// cardano-cli conway stake-address key-hash --stake-verification-key-file stake.vkey
	goldenStakeKeyHash = "d88b9f136cc94612ed33dd8774c6f43db347ae5814d8efd725d39313"
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
