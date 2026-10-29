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
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// poolOwnerExpected derives the plain stake key independently of the code
// under test: BIP32 derivation of m/1852'/1815'/account'/2/index through the
// library, k_L as the RFC 8032 seed, and crypto/ed25519 for the public key.
func poolOwnerExpected(
	t *testing.T,
	account, index uint32,
) (seed, pub []byte) {
	t.Helper()
	const harden = 0x80000000
	rootKey, err := bursa.GetRootKeyFromMnemonic(testKeyMnemonic, "")
	require.NoError(t, err)
	derived := rootKey.
		Derive(harden + 1852).
		Derive(harden + 1815).
		Derive(harden + account).
		Derive(2).
		Derive(index)
	seed = append([]byte(nil), derived.PrivateKey()[:32]...)
	pub = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return seed, pub
}

func readKeyFile(t *testing.T, path string) bursa.KeyFile {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var kf bursa.KeyFile
	require.NoError(t, json.Unmarshal(data, &kf))
	return kf
}

func writePoolOwner(
	t *testing.T,
	account, index uint32,
) (skey, vkey bursa.KeyFile) {
	t.Helper()
	dir := t.TempDir()
	skeyPath := filepath.Join(dir, "owner.skey")
	vkeyPath := filepath.Join(dir, "owner.vkey")
	require.NoError(t, RunKeyPoolOwner(
		testKeyMnemonic, "", "", skeyPath, vkeyPath, account, index,
	))
	return readKeyFile(t, skeyPath), readKeyFile(t, vkeyPath)
}

func TestRunKeyPoolOwner_FilesMatchIndependentDerivation(t *testing.T) {
	t.Parallel()
	seed, pub := poolOwnerExpected(t, 0, 0)
	skey, vkey := writePoolOwner(t, 0, 0)

	assert.Equal(t, "StakeSigningKeyShelley_ed25519", skey.Type)
	assert.Equal(t, "Stake Signing Key", skey.Description)
	assert.Equal(t, "5820"+hex.EncodeToString(seed), skey.CborHex)

	assert.Equal(t, "StakeVerificationKeyShelley_ed25519", vkey.Type)
	assert.Equal(t, "Stake Verification Key", vkey.Description)
	assert.Equal(t, "5820"+hex.EncodeToString(pub), vkey.CborHex)
}

func TestRunKeyPoolOwner_AccountAndIndexChangeKey(t *testing.T) {
	t.Parallel()
	base, _ := writePoolOwner(t, 0, 0)
	for _, tc := range []struct{ account, index uint32 }{{1, 0}, {0, 1}, {2, 3}} {
		skey, vkey := writePoolOwner(t, tc.account, tc.index)
		seed, pub := poolOwnerExpected(t, tc.account, tc.index)
		assert.NotEqual(t, base.CborHex, skey.CborHex)
		assert.Equal(t, "5820"+hex.EncodeToString(seed), skey.CborHex)
		assert.Equal(t, "5820"+hex.EncodeToString(pub), vkey.CborHex)
	}
}

func TestRunKeyPoolOwner_VKeyDiffersFromStakeKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stakeVKeyPath := filepath.Join(dir, "stake.vkey")
	require.NoError(t, RunKeyStake(
		testKeyMnemonic, "", "", "", stakeVKeyPath, 0, 0,
	))
	stakeVKey := readKeyFile(t, stakeVKeyPath)
	_, ownerVKey := writePoolOwner(t, 0, 0)
	assert.Equal(t, stakeVKey.Type, ownerVKey.Type)
	assert.NotEqual(t, stakeVKey.CborHex, ownerVKey.CborHex)
}

func TestRunKeyPoolOwner_VerificationKeyOnly(t *testing.T) {
	t.Parallel()
	vkeyPath := filepath.Join(t.TempDir(), "owner.vkey")
	require.NoError(t, RunKeyPoolOwner(
		testKeyMnemonic, "", "", "", vkeyPath, 0, 0,
	))
	_, pub := poolOwnerExpected(t, 0, 0)
	assert.Equal(
		t, "5820"+hex.EncodeToString(pub), readKeyFile(t, vkeyPath).CborHex,
	)
}

func TestRunKeyPoolOwner_MissingMnemonic(t *testing.T) {
	// Not t.Parallel: t.Setenv cannot run in a parallel test. MNEMONIC is
	// read before the mnemonic file, so it is cleared here.
	t.Setenv("MNEMONIC", "")
	missing := filepath.Join(t.TempDir(), "seed.txt")
	assert.Error(t, RunKeyPoolOwner("", missing, "", "-", "", 0, 0))
}

func TestRunKeyPoolOwner_RejectsSameKeyPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.skey")

	err := RunKeyPoolOwner(
		testKeyMnemonic, "", "", path, filepath.Join(dir, ".", "owner.skey"), 0, 0,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same file")

	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "no key file is written")
}

func TestRunKeyPoolOwner_RequiresDestination(t *testing.T) {
	t.Parallel()
	err := RunKeyPoolOwner(testKeyMnemonic, "", "", "", "", 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination")
}

// Not t.Parallel: captureStdout swaps the process-wide os.Stdout.
func TestRunKeyPoolOwner_DashPrintsPlainStakeSK(t *testing.T) {
	var err error
	out := captureStdout(t, func() {
		err = RunKeyPoolOwner(testKeyMnemonic, "", "", "-", "", 0, 0)
	})
	require.NoError(t, err)
	out = strings.TrimSpace(out)
	require.True(t, strings.HasPrefix(out, "stake_sk1"), "got %q", out)
	assert.False(t, strings.HasPrefix(out, "stake_xsk"))

	// The bech32 payload must decode to the 32-byte seed.
	hrp, data, err := bech32.Decode(out)
	require.NoError(t, err)
	assert.Equal(t, "stake_sk", hrp)
	raw, err := bech32.ConvertBits(data, 5, 8, false)
	require.NoError(t, err)
	seed, _ := poolOwnerExpected(t, 0, 0)
	assert.Equal(t, seed, raw)
}

// A witness made with the pool-owner signing file through `tx witness` must
// carry the plain public key and verify under it.
func TestRunTxWitness_PoolOwnerSigningKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	skeyPath := filepath.Join(dir, "owner.skey")
	require.NoError(t, RunKeyPoolOwner(
		testKeyMnemonic, "", "", skeyPath, "", 0, 0,
	))
	_, pub := poolOwnerExpected(t, 0, 0)

	txFile := filepath.Join("..", "..", "testdata", "conway-unsigned.tx")
	witFile := filepath.Join(dir, "owner.witness")
	require.NoError(t, RunTxWitness(txFile, skeyPath, witFile, ""))

	raw, err := bursa.ReadCborInputFile(witFile)
	require.NoError(t, err)
	wit, err := bursa.DecodeWitness(raw)
	require.NoError(t, err)
	assert.Equal(t, []byte(pub), wit.Vkey)

	txBytes, _, err := readTxFile(txFile, "")
	require.NoError(t, err)
	txType, err := ledger.DetermineTransactionType(txBytes)
	require.NoError(t, err)
	tx, err := ledger.NewTransactionFromCbor(txType, txBytes)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub, tx.Hash().Bytes(), wit.Signature))
}
