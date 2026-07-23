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
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/kes"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/vrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capabilityMnemonic is the canonical CIP-1852 test vector mnemonic.
// DO NOT USE FOR REAL FUNDS.
const capabilityMnemonic = "abandon abandon abandon abandon " +
	"abandon abandon abandon abandon " +
	"abandon abandon abandon about"

// Golden verification-key cborHex values derived from the "abandon"
// mnemonic, cross-checked against the cardano-cli-compatible vectors
// already asserted in internal/cli/cardano_cli_compat_test.go.
const (
	// m/1852'/1815'/0'/0/0 payment (and Calidus, same path)
	capPaymentVKeyCborHex = "58207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a"
)

func capabilityAccountKey(t *testing.T) bip32.XPrv {
	t.Helper()
	rootKey, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)
	accountKey, err := GetAccountKey(rootKey, 0)
	require.NoError(t, err)
	return accountKey
}

// --- Root / account key files -------------------------------------------

func TestGetRootSKey(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)

	kf, err := GetRootSKey(rootKey)
	require.NoError(t, err)
	assert.Equal(t, "SigningKeyShelley_ed25519", kf.Type)
	assert.Equal(t, "Root Signing Key", kf.Description)
	// Signing key files carry the first 32 bytes (k_L) CBOR-wrapped.
	require.GreaterOrEqual(t, len(kf.CborHex), 4)
	assert.Equal(t, "5820", kf.CborHex[:4])

	// Deterministic for the same mnemonic.
	kf2, err := GetRootSKey(rootKey)
	require.NoError(t, err)
	assert.Equal(t, kf.CborHex, kf2.CborHex)
}

func TestGetAccountVKeyAndSKey(t *testing.T) {
	accountKey := capabilityAccountKey(t)

	vkey, err := GetAccountVKey(accountKey)
	require.NoError(t, err)
	assert.Equal(t, "AccountVerificationKeyShelley_ed25519", vkey.Type)
	assert.Equal(t, "Account Verification Key", vkey.Description)
	assert.Equal(t, "5820", vkey.CborHex[:4])

	skey, err := GetAccountSKey(accountKey)
	require.NoError(t, err)
	assert.Equal(t, "AccountSigningKeyShelley_ed25519", skey.Type)
	assert.Equal(t, "Account Signing Key", skey.Description)
	assert.Equal(t, "5820", skey.CborHex[:4])

	// The account vkey CBOR must decode to the raw 32-byte public key.
	raw := decodeCborBytes(t, vkey.CborHex)
	assert.Equal(t, []byte(accountKey.Public().PublicKey()), raw)
}

func TestGetExtendedPrivateKey(t *testing.T) {
	accountKey := capabilityAccountKey(t)
	paymentKey, err := GetPaymentKey(accountKey, 0)
	require.NoError(t, err)

	ext := GetExtendedPrivateKey(paymentKey)
	// xprv is 96 bytes: 64-byte private key || 32-byte chain code.
	assert.Len(t, []byte(ext), 96)
	assert.Equal(t, paymentKey.PrivateKey(), ext.PrivateKey())
	assert.Equal(t, paymentKey.ChainCode(), ext.ChainCode())

	// It is a defensive copy: mutating the result must not touch input.
	origFirst := paymentKey.PrivateKey()[0]
	ext[0] ^= 0xff
	assert.Equal(t, origFirst, paymentKey.PrivateKey()[0])
}

// --- Calidus keys (CIP-88/CIP-151) --------------------------------------

func TestGetCalidusKeyMatchesPaymentPath(t *testing.T) {
	accountKey := capabilityAccountKey(t)

	// Calidus uses the same path as payment (role 0, index): it must
	// produce the identical public key as the golden payment vkey.
	calidusKey, err := GetCalidusKey(accountKey, 0)
	require.NoError(t, err)

	vkey, err := GetCalidusVKey(calidusKey)
	require.NoError(t, err)
	assert.Equal(t, "CalidusVerificationKeyShelley_ed25519", vkey.Type)
	assert.Equal(t, capPaymentVKeyCborHex, vkey.CborHex)

	skey, err := GetCalidusSKey(calidusKey)
	require.NoError(t, err)
	assert.Equal(t, "CalidusSigningKeyShelley_ed25519", skey.Type)
	assert.Equal(t, "5820", skey.CborHex[:4])

	extSkey, err := GetCalidusExtendedSKey(calidusKey)
	require.NoError(t, err)
	assert.Equal(
		t,
		"CalidusExtendedSigningKeyShelley_ed25519_bip32",
		extSkey.Type,
	)
	// Extended key format is 128 bytes -> CBOR bytestring prefix 5880.
	assert.Equal(t, "5880", extSkey.CborHex[:4])
}

func TestGetCalidusKeyInvalidIndex(t *testing.T) {
	accountKey := capabilityAccountKey(t)
	_, err := GetCalidusKey(accountKey, 0x80000000)
	assert.ErrorIs(t, err, ErrInvalidDerivationIndex)
}

// --- Governance keys (CIP-0105): DRep / Committee -----------------------

func TestGetDRepKeyFiles(t *testing.T) {
	accountKey := capabilityAccountKey(t)

	drepKey, err := GetDRepKey(accountKey, 0)
	require.NoError(t, err)
	// DRep path is role 3.
	assert.Equal(
		t,
		[]byte(accountKey.Derive(3).Derive(0).Public().PublicKey()),
		[]byte(drepKey.Public().PublicKey()),
	)

	vkey, err := GetDRepVKey(drepKey)
	require.NoError(t, err)
	assert.Equal(t, "DRepVerificationKeyShelley_ed25519", vkey.Type)
	assert.Equal(t, "5820", vkey.CborHex[:4])

	skey, err := GetDRepSKey(drepKey)
	require.NoError(t, err)
	assert.Equal(t, "DRepSigningKeyShelley_ed25519", skey.Type)
	assert.Equal(t, "5820", skey.CborHex[:4])

	_, err = GetDRepKey(accountKey, 0x80000000)
	assert.ErrorIs(t, err, ErrInvalidDerivationIndex)
}

func TestGetCommitteeColdKeyFiles(t *testing.T) {
	accountKey := capabilityAccountKey(t)

	ccKey, err := GetCommitteeColdKey(accountKey, 0)
	require.NoError(t, err)
	// Committee cold path is role 4.
	assert.Equal(
		t,
		[]byte(accountKey.Derive(4).Derive(0).Public().PublicKey()),
		[]byte(ccKey.Public().PublicKey()),
	)

	vkey, err := GetCommitteeColdVKey(ccKey)
	require.NoError(t, err)
	assert.Equal(
		t,
		"CommitteeColdVerificationKeyShelley_ed25519",
		vkey.Type,
	)
	assert.Equal(t, "5820", vkey.CborHex[:4])

	_, err = GetCommitteeColdKey(accountKey, 0x80000000)
	assert.ErrorIs(t, err, ErrInvalidDerivationIndex)
}

func TestGetCommitteeHotKeyFiles(t *testing.T) {
	accountKey := capabilityAccountKey(t)

	hotKey, err := GetCommitteeHotKey(accountKey, 0)
	require.NoError(t, err)
	// Committee hot path is role 5.
	assert.Equal(
		t,
		[]byte(accountKey.Derive(5).Derive(0).Public().PublicKey()),
		[]byte(hotKey.Public().PublicKey()),
	)

	vkey, err := GetCommitteeHotVKey(hotKey)
	require.NoError(t, err)
	assert.Equal(
		t,
		"CommitteeHotVerificationKeyShelley_ed25519",
		vkey.Type,
	)
	assert.Equal(t, "5820", vkey.CborHex[:4])

	_, err = GetCommitteeHotKey(accountKey, 0x80000000)
	assert.ErrorIs(t, err, ErrInvalidDerivationIndex)
}

// Governance roles must all derive distinct keys.
func TestGovernanceRolesAreDistinct(t *testing.T) {
	accountKey := capabilityAccountKey(t)

	drep, err := GetDRepKey(accountKey, 0)
	require.NoError(t, err)
	cold, err := GetCommitteeColdKey(accountKey, 0)
	require.NoError(t, err)
	hot, err := GetCommitteeHotKey(accountKey, 0)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(drep.Public().PublicKey(), cold.Public().PublicKey()))
	assert.False(t, bytes.Equal(cold.Public().PublicKey(), hot.Public().PublicKey()))
	assert.False(t, bytes.Equal(drep.Public().PublicKey(), hot.Public().PublicKey()))
}

// --- VRF keys ------------------------------------------------------------

func TestVRFDerivation(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)

	seed, err := GetVRFSeed(rootKey, 0)
	require.NoError(t, err)
	assert.Len(t, seed, vrf.SeedSize)

	// Seed derivation is deterministic and index-sensitive.
	seedAgain, err := GetVRFSeed(rootKey, 0)
	require.NoError(t, err)
	assert.Equal(t, seed, seedAgain)
	seed1, err := GetVRFSeed(rootKey, 1)
	require.NoError(t, err)
	assert.NotEqual(t, seed, seed1)

	pub, sec, err := GetVRFKeyPair(seed)
	require.NoError(t, err)
	assert.Len(t, pub, vrf.PublicKeySize)

	vkey, err := GetVRFVKey(pub)
	require.NoError(t, err)
	assert.Equal(t, "VRFVerificationKey_PraosVRF", vkey.Type)
	assert.Equal(t, pub, decodeCborBytes(t, vkey.CborHex))

	skey, err := GetVRFSKey(sec)
	require.NoError(t, err)
	assert.Equal(t, "VRFSigningKey_PraosVRF", skey.Type)
	assert.Equal(t, sec, decodeCborBytes(t, skey.CborHex))
}

func TestVRFSeedInvalidIndex(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)
	_, err = GetVRFSeed(rootKey, 0x80000000)
	assert.ErrorIs(t, err, ErrInvalidDerivationIndex)
}

func TestVRFKeyPairInvalidSeedSize(t *testing.T) {
	_, _, err := GetVRFKeyPair([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid seed size")
}

// --- KES keys ------------------------------------------------------------

func TestKESDerivation(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)

	seed, err := GetKESSeed(rootKey, 0)
	require.NoError(t, err)
	assert.Len(t, seed, kes.SeedSize)

	// KES and VRF seeds use different domain separators -> differ.
	vrfSeed, err := GetVRFSeed(rootKey, 0)
	require.NoError(t, err)
	assert.NotEqual(t, seed, vrfSeed)

	secKey, pub, err := GetKESKeyPair(seed)
	require.NoError(t, err)
	require.NotNil(t, secKey)
	assert.Len(t, pub, 32)

	vkey, err := GetKESVKey(pub)
	require.NoError(t, err)
	assert.Equal(t, "KESVerificationKey_PraosV2", vkey.Type)
	assert.Equal(t, pub, decodeCborBytes(t, vkey.CborHex))

	skey, err := GetKESSKey(secKey)
	require.NoError(t, err)
	assert.Equal(t, "KESSigningKey_PraosV2", skey.Type)
	assert.NotEmpty(t, skey.CborHex)
}

func TestKESSeedInvalidIndex(t *testing.T) {
	rootKey, err := GetRootKeyFromMnemonic(capabilityMnemonic, "")
	require.NoError(t, err)
	_, err = GetKESSeed(rootKey, 0x80000000)
	assert.ErrorIs(t, err, ErrInvalidDerivationIndex)
}

func TestKESKeyPairInvalidSeedSize(t *testing.T) {
	_, _, err := GetKESKeyPair([]byte{0x00})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid seed size")
}

// --- Certificate building ------------------------------------------------

func TestCreatePoolRegistrationCertificate(t *testing.T) {
	var operator lcommon.PoolKeyHash
	var vrfHash lcommon.VrfKeyHash
	for i := range operator {
		operator[i] = byte(i + 1)
	}
	for i := range vrfHash {
		vrfHash[i] = byte(i + 100)
	}
	reward := make([]byte, 29)
	reward[0] = 0xe1

	cert := &PoolRegistrationCertificate{
		Operator:      operator,
		VrfKeyHash:    vrfHash,
		Pledge:        1_000_000_000,
		Cost:          340_000_000,
		MarginNum:     3,
		MarginDenom:   100,
		RewardAccount: reward,
		PoolOwners:    []lcommon.AddrKeyHash{lcommon.AddrKeyHash(operator)},
		Relays:        nil,
	}

	cborBytes, err := CreatePoolRegistrationCertificate(cert)
	require.NoError(t, err)
	require.NotEmpty(t, cborBytes)

	// Decode the outer array and assert cert type + scalar fields.
	var decoded []cbor.RawMessage
	_, err = cbor.Decode(cborBytes, &decoded)
	require.NoError(t, err)
	require.Len(t, decoded, 10)

	var certType uint
	_, err = cbor.Decode(decoded[0], &certType)
	require.NoError(t, err)
	assert.Equal(t, uint(3), certType, "pool registration is cert type 3")

	var pledge uint64
	_, err = cbor.Decode(decoded[3], &pledge)
	require.NoError(t, err)
	assert.Equal(t, uint64(1_000_000_000), pledge)

	var cost uint64
	_, err = cbor.Decode(decoded[4], &cost)
	require.NoError(t, err)
	assert.Equal(t, uint64(340_000_000), cost)
}

func TestCreatePoolRegistrationCertificateWithMetadata(t *testing.T) {
	var operator lcommon.PoolKeyHash
	var vrfHash lcommon.VrfKeyHash
	metaHash := make([]byte, 32)
	for i := range metaHash {
		metaHash[i] = 0xab
	}
	reward := make([]byte, 29)
	reward[0] = 0xe1

	cert := &PoolRegistrationCertificate{
		Operator:      operator,
		VrfKeyHash:    vrfHash,
		Pledge:        1,
		Cost:          1,
		MarginNum:     1,
		MarginDenom:   1,
		RewardAccount: reward,
		PoolOwners:    []lcommon.AddrKeyHash{},
		Relays:        nil,
		MetadataURL:   "https://example.com/pool.json",
		MetadataHash:  lcommon.NewBlake2b256(metaHash),
	}

	cborBytes, err := CreatePoolRegistrationCertificate(cert)
	require.NoError(t, err)
	// Metadata URL should appear in the encoded bytes.
	assert.Contains(
		t,
		string(cborBytes),
		"https://example.com/pool.json",
	)
}

func TestCreatePoolRegistrationCertificateZeroDenom(t *testing.T) {
	cert := &PoolRegistrationCertificate{
		MarginNum:     1,
		MarginDenom:   0,
		RewardAccount: make([]byte, 29),
	}
	_, err := CreatePoolRegistrationCertificate(cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denominator")
}

func TestCreatePoolRetirementCertificate(t *testing.T) {
	var poolHash lcommon.PoolKeyHash
	for i := range poolHash {
		poolHash[i] = byte(i + 1)
	}

	params := &PoolRetirementCertificateParams{
		PoolKeyHash: poolHash,
		Epoch:       500,
	}

	cborBytes, err := CreatePoolRetirementCertificate(params)
	require.NoError(t, err)

	var decoded []cbor.RawMessage
	_, err = cbor.Decode(cborBytes, &decoded)
	require.NoError(t, err)
	require.Len(t, decoded, 3)

	var certType uint
	_, err = cbor.Decode(decoded[0], &certType)
	require.NoError(t, err)
	assert.Equal(t, uint(4), certType, "pool retirement is cert type 4")

	var epoch uint64
	_, err = cbor.Decode(decoded[2], &epoch)
	require.NoError(t, err)
	assert.Equal(t, uint64(500), epoch)

	// Retirement CBOR is deterministic.
	cborBytes2, err := CreatePoolRetirementCertificate(params)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(cborBytes), hex.EncodeToString(cborBytes2))
}

// --- Address building ----------------------------------------------------

// Authoritative cardano-cli address vectors for the "abandon" mnemonic
// (mainnet), matching internal/cli/cardano_cli_compat_test.go.
const (
	capMainnetBaseAddr  = "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv"
	capMainnetStakeAddr = "stake1u8j40zgr2gy4788kl54h6x3gu0pukq5lfr8nflufpg5dzaskqlx2l"
)

func TestGetAddressBech32(t *testing.T) {
	accountKey := capabilityAccountKey(t)

	mainnet, err := GetAddress(accountKey, "mainnet", 0)
	require.NoError(t, err)
	assert.Equal(t, capMainnetBaseAddr, mainnet.String(),
		"mainnet base address must match cardano-cli vector")
	assert.True(t, strings.HasPrefix(mainnet.String(), "addr1"))

	testnet, err := GetAddress(accountKey, "preprod", 0)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(testnet.String(), "addr_test1"),
		"testnet base address must use addr_test1 prefix, got %q",
		testnet.String())

	// Payment credential (network-independent) is the same on both nets.
	assert.NotEqual(t, mainnet.String(), testnet.String())
}

func TestGetRewardAddressBech32(t *testing.T) {
	accountKey := capabilityAccountKey(t)
	stakeKey, err := GetStakeKey(accountKey, 0)
	require.NoError(t, err)
	stakeVKey, err := GetStakeVKey(stakeKey)
	require.NoError(t, err)

	mainnet, err := GetRewardAddress(stakeVKey, "mainnet")
	require.NoError(t, err)
	assert.Equal(t, capMainnetStakeAddr, mainnet.String(),
		"mainnet reward address must match cardano-cli vector")
	assert.True(t, strings.HasPrefix(mainnet.String(), "stake1"))

	testnet, err := GetRewardAddress(stakeVKey, "preprod")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(testnet.String(), "stake_test1"),
		"testnet reward address must use stake_test1 prefix, got %q",
		testnet.String())
}

func TestGetRewardAddressErrors(t *testing.T) {
	accountKey := capabilityAccountKey(t)
	stakeKey, err := GetStakeKey(accountKey, 0)
	require.NoError(t, err)
	stakeVKey, err := GetStakeVKey(stakeKey)
	require.NoError(t, err)

	_, err = GetRewardAddress(stakeVKey, "")
	assert.ErrorIs(t, err, ErrInvalidNetwork)

	_, err = GetRewardAddress(stakeVKey, "bogusnet")
	assert.ErrorIs(t, err, ErrInvalidNetwork)

	// Malformed CBOR hex in the key file surfaces an error.
	bad := KeyFile{CborHex: "zzzz"}
	_, err = GetRewardAddress(bad, "mainnet")
	assert.Error(t, err)
}

// decodeCborBytes decodes a CBOR-wrapped byte string from hex.
func decodeCborBytes(t *testing.T, cborHex string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(cborHex)
	require.NoError(t, err)
	var out []byte
	_, err = cbor.Decode(raw, &out)
	require.NoError(t, err)
	return out
}
