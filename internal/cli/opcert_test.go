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

package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deterministic test material.
var (
	// 32-byte cold signing key seed.
	testColdSkeySeed = mustHex(
		"1111111111111111111111111111111111111111111111111111111111111111",
	)
	// 32-byte KES verification key.
	testKESVkey = mustHex(
		"2222222222222222222222222222222222222222222222222222222222222222",
	)
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestEncodeOpCertCBORShape verifies that encodeOpCertCBOR emits the canonical
// 2-element NodeOperationalCertificate structure:
//
//	[[kes_vkey, counter, kes_period, signature], cold_vkey]
//
// with a 32-byte cold verification key as the outer array's second element.
func TestEncodeOpCertCBORShape(t *testing.T) {
	opCert, err := bursa.CreateOperationalCertificate(
		testKESVkey,
		7,  // counter / issue number
		42, // kes period
		testColdSkeySeed,
	)
	require.NoError(t, err)

	// The cold vkey must be carried on the certificate and be the correct
	// public key derived from the cold seed.
	expectedColdVkey := ed25519.NewKeyFromSeed(testColdSkeySeed).
		Public().(ed25519.PublicKey)
	assert.Equal(t, []byte(expectedColdVkey), opCert.ColdVkey)
	require.Len(t, opCert.ColdVkey, 32)

	cborHex, err := encodeOpCertCBOR(opCert)
	require.NoError(t, err)

	raw, err := hex.DecodeString(cborHex)
	require.NoError(t, err)

	var outer []any
	_, err = cbor.Decode(raw, &outer)
	require.NoError(t, err)

	// Outer array: 2 elements.
	require.Len(t, outer, 2, "outer array must have exactly 2 elements")

	// Element 0: inner 4-element cert array.
	inner, ok := outer[0].([]any)
	require.True(t, ok, "outer[0] must be an array")
	require.Len(t, inner, 4, "inner cert array must have 4 elements")

	kesVkey, ok := inner[0].([]byte)
	require.True(t, ok)
	assert.Equal(t, testKESVkey, kesVkey)

	// Element 1: 32-byte cold vkey.
	coldVkey, ok := outer[1].([]byte)
	require.True(t, ok, "outer[1] (cold_vkey) must be bytes")
	require.Len(t, coldVkey, 32, "cold_vkey must be 32 bytes")
	assert.Equal(t, []byte(expectedColdVkey), coldVkey)
}

// TestOpCertEncodeDecodeRoundTrip proves that a certificate emitted by
// encodeOpCertCBOR (wrapped in the NodeOperationalCertificate text envelope)
// can be decoded again by bursa's own decoder. This is the round-trip the bug
// broke: the old bare 4-tuple failed bursa's 2-element outer-array requirement.
func TestOpCertEncodeDecodeRoundTrip(t *testing.T) {
	const (
		counter   = uint64(3)
		kesPeriod = uint64(100)
	)
	opCert, err := bursa.CreateOperationalCertificate(
		testKESVkey,
		counter,
		kesPeriod,
		testColdSkeySeed,
	)
	require.NoError(t, err)

	cborHex, err := encodeOpCertCBOR(opCert)
	require.NoError(t, err)

	envelope := map[string]string{
		"type":        "NodeOperationalCertificate",
		"description": "Operational Certificate",
		"cborHex":     cborHex,
	}
	data, err := json.Marshal(envelope)
	require.NoError(t, err)

	loaded, err := bursa.LoadKeyFromBytes(data)
	require.NoError(t, err, "bursa must be able to decode its own op-cert output")

	assert.Equal(t, testKESVkey, loaded.VKey)
	assert.Equal(t, counter, loaded.OpCertIssueNumber)
	assert.Equal(t, kesPeriod, loaded.OpCertKesPeriod)
	assert.Equal(t, opCert.ColdSignature, loaded.OpCertSignature)
	assert.Equal(t, opCert.ColdVkey, loaded.OpCertColdVKey)

	expectedColdVkey := ed25519.NewKeyFromSeed(testColdSkeySeed).
		Public().(ed25519.PublicKey)
	assert.Equal(t, []byte(expectedColdVkey), loaded.OpCertColdVKey)
}

// TestRunCertOpCertRoundTrip drives the full CLI command end-to-end: it writes
// KES vkey and cold skey input files, runs RunCertOpCert to produce the cert
// file, then decodes that file with bursa.LoadKeyFromFile.
func TestRunCertOpCertRoundTrip(t *testing.T) {
	dir := t.TempDir()

	kesVkeyFile := createTestVkeyFile(
		t,
		dir,
		"kes.vkey",
		"KesVerificationKey_ed25519_kes_2^6",
		"KES Verification Key",
		"5820"+hex.EncodeToString(testKESVkey),
	)
	coldSkeyFile := createTestVkeyFile(
		t,
		dir,
		"cold.skey",
		"StakePoolSigningKey_ed25519",
		"Stake Pool Cold Signing Key",
		"5820"+hex.EncodeToString(testColdSkeySeed),
	)
	outFile := filepath.Join(dir, "node.cert")

	err := RunCertOpCert(kesVkeyFile, coldSkeyFile, outFile, 5, 250)
	require.NoError(t, err)

	// The emitted file must be a valid NodeOperationalCertificate envelope
	// that bursa can load back.
	raw, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var env struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Equal(t, "NodeOperationalCertificate", env.Type)

	loaded, err := bursa.LoadKeyFromFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, testKESVkey, loaded.VKey)
	assert.Equal(t, uint64(5), loaded.OpCertIssueNumber)
	assert.Equal(t, uint64(250), loaded.OpCertKesPeriod)
	require.Len(t, loaded.OpCertColdVKey, 32)

	expectedColdVkey := ed25519.NewKeyFromSeed(testColdSkeySeed).
		Public().(ed25519.PublicKey)
	assert.Equal(t, []byte(expectedColdVkey), loaded.OpCertColdVKey)
}
