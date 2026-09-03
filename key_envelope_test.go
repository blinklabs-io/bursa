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

package bursa

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const envelopeTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// envelopeCorpus is one valid envelope of every type parseKeyEnvelope accepts,
// keyed by the envelope type string that will be written into the JSON file.
type envelopeCase struct {
	name    string
	keyType string
	cborHex string
}

// buildEnvelopeCorpus derives a real key of every supported envelope shape from
// a fixed mnemonic, so the negative vectors below mutate genuine material
// rather than hand-written bytes that could fail for an unrelated reason.
func buildEnvelopeCorpus(t *testing.T) []envelopeCase {
	t.Helper()

	rootKey, err := GetRootKeyFromMnemonic(envelopeTestMnemonic, "")
	require.NoError(t, err)
	accountKey, err := GetAccountKey(rootKey, 0)
	require.NoError(t, err)
	paymentKey, err := GetPaymentKey(accountKey, 0)
	require.NoError(t, err)

	paymentVKey, err := GetPaymentVKey(paymentKey)
	require.NoError(t, err)
	paymentExtSKey, err := GetPaymentExtendedSKey(paymentKey)
	require.NoError(t, err)
	nonExtendedSeedCbor, err := cbor.Encode(make([]byte, 32))
	require.NoError(t, err)

	vrfSeed, err := GetVRFSeed(rootKey, 0)
	require.NoError(t, err)
	vrfPub, vrfSec, err := GetVRFKeyPair(vrfSeed)
	require.NoError(t, err)
	vrfVKey, err := GetVRFVKey(vrfPub)
	require.NoError(t, err)
	vrfSKey, err := GetVRFSKey(vrfSec)
	require.NoError(t, err)

	kesSeed, err := GetKESSeed(rootKey, 0)
	require.NoError(t, err)
	kesSec, kesPub, err := GetKESKeyPair(kesSeed)
	require.NoError(t, err)
	kesVKey, err := GetKESVKey(kesPub)
	require.NoError(t, err)
	kesSKey, err := GetKESSKey(kesSec)
	require.NoError(t, err)

	opCert, err := CreateOperationalCertificate(
		kesPub,
		1,
		0,
		paymentSKeySeed(t, paymentKey),
	)
	require.NoError(t, err)
	opCertCbor, err := cbor.Encode(
		[]any{
			[]any{
				opCert.KesVkey,
				opCert.IssueNumber,
				opCert.KesPeriod,
				opCert.ColdSignature,
			},
			opCert.ColdVkey,
		},
	)
	require.NoError(t, err)

	return []envelopeCase{
		{
			"ed25519 vkey",
			"PaymentVerificationKeyShelley_ed25519",
			paymentVKey.CborHex,
		},
		{
			"ed25519 skey",
			"PaymentSigningKeyShelley_ed25519",
			hex.EncodeToString(nonExtendedSeedCbor),
		},
		{
			"extended skey",
			"PaymentExtendedSigningKeyShelley_ed25519_bip32",
			paymentExtSKey.CborHex,
		},
		{"VRF vkey", "VRFVerificationKey_PraosVRF", vrfVKey.CborHex},
		{"VRF skey", "VRFSigningKey_PraosVRF", vrfSKey.CborHex},
		{"KES vkey", "KESVerificationKey_PraosV2", kesVKey.CborHex},
		{"KES skey", "KESSigningKey_PraosV2", kesSKey.CborHex},
		{
			"operational certificate",
			"NodeOperationalCertificate",
			hex.EncodeToString(opCertCbor),
		},
	}
}

// paymentSKeySeed derives the raw 32-byte seed from an extended private key,
// which is the form CreateOperationalCertificate expects.
func paymentSKeySeed(t *testing.T, key bip32.XPrv) []byte {
	t.Helper()
	return append([]byte(nil), key.PrivateKey()[:32]...)
}

func envelopeJSON(t *testing.T, keyType, cborHex string) []byte {
	t.Helper()
	data, err := json.Marshal(KeyFile{
		Type:        keyType,
		Description: "test envelope",
		CborHex:     cborHex,
	})
	require.NoError(t, err)
	return data
}

// TestKeyEnvelopeAcceptsValidVectors is the positive control for the two
// negative tests below: every corpus entry must still load cleanly, so a
// rejection there is attributable to the mutation and not to the corpus.
func TestKeyEnvelopeAcceptsValidVectors(t *testing.T) {
	for _, tc := range buildEnvelopeCorpus(t) {
		t.Run(tc.name, func(t *testing.T) {
			loaded, err := LoadKeyFromBytes(
				envelopeJSON(t, tc.keyType, tc.cborHex),
			)
			require.NoError(t, err)
			assert.Equal(t, tc.keyType, loaded.Type)
			assert.NotEmpty(t, loaded.VKey)
		})
	}
}

// TestKeyEnvelopeRejectsTrailingData covers the first acceptance criterion: a
// decoder that stops at the first CBOR value would silently accept a file
// carrying a second, unread payload after the key.
func TestKeyEnvelopeRejectsTrailingData(t *testing.T) {
	for _, tc := range buildEnvelopeCorpus(t) {
		t.Run(tc.name, func(t *testing.T) {
			// A single 0x00 (CBOR unsigned 0) appended after the encoded value.
			polluted := tc.cborHex + "00"
			_, err := LoadKeyFromBytes(envelopeJSON(t, tc.keyType, polluted))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "trailing byte")
		})
	}
}

// TestExtendedEnvelopeRejectsMismatchedPublicKey covers the second acceptance
// criterion for every extended Ed25519 envelope type: the embedded public key
// is not the key's identity until it has been checked against one derived from
// the private half.
func TestExtendedEnvelopeRejectsMismatchedPublicKey(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(envelopeTestMnemonic, "")
	require.NoError(t, err)
	accountKey, err := GetAccountKey(rootKey, 0)
	require.NoError(t, err)
	paymentKey, err := GetPaymentKey(accountKey, 0)
	require.NoError(t, err)
	extSKey, err := GetPaymentExtendedSKey(paymentKey)
	require.NoError(t, err)

	raw, err := hex.DecodeString(extSKey.CborHex)
	require.NoError(t, err)
	var keyBytes []byte
	_, err = cbor.Decode(raw, &keyBytes)
	require.NoError(t, err)
	require.Len(t, keyBytes, 128)

	// Flip one bit of the embedded public key, leaving the private half and the
	// chain code intact.
	tampered := make([]byte, len(keyBytes))
	copy(tampered, keyBytes)
	tampered[64] ^= 0x01
	tamperedCbor, err := cbor.Encode(tampered)
	require.NoError(t, err)
	tamperedHex := hex.EncodeToString(tamperedCbor)

	extendedTypes := []string{
		"PaymentExtendedSigningKeyShelley_ed25519_bip32",
		"StakeExtendedSigningKeyShelley_ed25519_bip32",
		"DRepExtendedSigningKeyShelley_ed25519_bip32",
		"CommitteeColdExtendedSigningKeyShelley_ed25519_bip32",
		"CommitteeHotExtendedSigningKeyShelley_ed25519_bip32",
		"StakePoolExtendedSigningKeyShelley_ed25519_bip32",
		"PolicyExtendedSigningKeyShelley_ed25519_bip32",
	}
	for _, keyType := range extendedTypes {
		t.Run(keyType, func(t *testing.T) {
			_, err := LoadKeyFromBytes(envelopeJSON(t, keyType, tamperedHex))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "does not match")
		})
	}
}

// TestExtendedEnvelopeReturnsDerivedIdentity covers the third acceptance
// criterion: the identity handed back is the derived one, not the bytes the
// file happened to carry.
func TestExtendedEnvelopeReturnsDerivedIdentity(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(envelopeTestMnemonic, "")
	require.NoError(t, err)
	accountKey, err := GetAccountKey(rootKey, 0)
	require.NoError(t, err)
	paymentKey, err := GetPaymentKey(accountKey, 0)
	require.NoError(t, err)
	extSKey, err := GetPaymentExtendedSKey(paymentKey)
	require.NoError(t, err)

	loaded, err := LoadKeyFromBytes(
		envelopeJSON(
			t,
			"PaymentExtendedSigningKeyShelley_ed25519_bip32",
			extSKey.CborHex,
		),
	)
	require.NoError(t, err)
	assert.Equal(t, []byte(paymentKey.Public().PublicKey()), loaded.VKey)
}

// TestVRFEnvelopeRejectsMismatchedPublicKey covers the cardano-cli VRF signing
// key form, which is the other envelope that carries a public key alongside the
// private material.
func TestVRFEnvelopeRejectsMismatchedPublicKey(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(envelopeTestMnemonic, "")
	require.NoError(t, err)
	seed, err := GetVRFSeed(rootKey, 0)
	require.NoError(t, err)
	pub, sec, err := GetVRFKeyPair(seed)
	require.NoError(t, err)

	// cardano-cli stores seed (32) || public key (32).
	combined := make([]byte, 0, len(sec)+len(pub))
	combined = append(combined, sec...)
	combined = append(combined, pub...)

	valid, err := cbor.Encode(combined)
	require.NoError(t, err)
	loaded, err := LoadKeyFromBytes(
		envelopeJSON(t, "VRFSigningKey_PraosVRF", hex.EncodeToString(valid)),
	)
	require.NoError(t, err)
	assert.Equal(t, pub, loaded.VKey)

	combined[len(sec)] ^= 0x01
	tampered, err := cbor.Encode(combined)
	require.NoError(t, err)
	_, err = LoadKeyFromBytes(
		envelopeJSON(t, "VRFSigningKey_PraosVRF", hex.EncodeToString(tampered)),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}
