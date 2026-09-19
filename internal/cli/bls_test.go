// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/stretchr/testify/require"
)

func TestRunKeyBLSWritesCardanoCLIEnvelopes(t *testing.T) {
	dir := t.TempDir()
	signingPath := filepath.Join(dir, "bls.skey")
	verificationPath := filepath.Join(dir, "bls.vkey")
	registrationPath := filepath.Join(dir, "bls.json")

	require.NoError(t, RunKeyBLS(signingPath, verificationPath, registrationPath))

	var registration struct {
		PublicKey       string `json:"publicKey"`
		PossessionProof string `json:"possessionProof"`
	}
	data, err := os.ReadFile(registrationPath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &registration))
	publicKey, err := hex.DecodeString(registration.PublicKey)
	require.NoError(t, err)
	proof, err := hex.DecodeString(registration.PossessionProof)
	require.NoError(t, err)
	require.Len(t, publicKey, bursa.BLSPublicKeySize)
	require.Len(t, proof, bursa.BLSPossessionProofSize)

	for _, path := range []string{signingPath, verificationPath, registrationPath} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode())
	}

	type envelopeTest struct {
		Type string
		Key  []byte
	}
	for path, want := range map[string]envelopeTest{
		signingPath:      {Type: "BlsSigningKey"},
		verificationPath: {Type: "BlsVerificationKey", Key: publicKey},
	} {
		var envelope bursa.KeyFile
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &envelope))
		require.Equal(t, want.Type, envelope.Type)
		cborData, err := hex.DecodeString(envelope.CborHex)
		require.NoError(t, err)
		var keyBytes []byte
		_, err = cbor.Decode(cborData, &keyBytes)
		require.NoError(t, err)
		if want.Key != nil {
			require.Equal(t, want.Key, keyBytes)
		} else {
			require.Len(t, keyBytes, bursa.BLSSecretKeySize)
		}
	}
}

func TestRunKeyBLSRestrictsExistingRegistrationFile(t *testing.T) {
	dir := t.TempDir()
	registrationPath := filepath.Join(dir, "bls.json")
	require.NoError(t, os.WriteFile(registrationPath, []byte("old"), 0o644))
	require.NoError(t, RunKeyBLS("", "", registrationPath))

	info, err := os.Stat(registrationPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestRunKeyBLSRejectsCollidingOutputPaths(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "bls.skey"),
		filepath.Join(dir, "bls.vkey"),
		filepath.Join(dir, "bls.json"),
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			args := append([]string(nil), paths...)
			args[j] = args[i]
			err := RunKeyBLS(args[0], args[1], args[2])
			require.Error(t, err, "paths %q and %q should be rejected", args[i], args[j])
			require.ErrorContains(t, err, "resolve to the same file")
		}
	}
}

func TestRunKeyBLSRejectsSymlinkedOutputPaths(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	linkDir := filepath.Join(dir, "link")
	require.NoError(t, os.Mkdir(filepath.Join(shared), 0o700))
	require.NoError(t, os.Symlink(shared, linkDir))

	err := RunKeyBLS(
		filepath.Join(shared, "bls.skey"),
		filepath.Join(linkDir, "bls.skey"),
		filepath.Join(dir, "bls.json"),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "resolve to the same file")
}

func TestRunKeyBLSRegistrationPopulatesDijkstraLeiosKey(t *testing.T) {
	key, err := bursa.NewBLSKeyFromIKM(bytes.Repeat([]byte{0x42}, bursa.BLSSecretKeySize))
	require.NoError(t, err)

	field, err := cbor.Encode([][]byte{key.PublicKey, key.PossessionProof})
	require.NoError(t, err)
	var decoded [][]byte
	_, err = cbor.Decode(field, &decoded)
	require.NoError(t, err)
	require.Equal(t, [][]byte{key.PublicKey, key.PossessionProof}, decoded)
	require.Len(t, decoded[0], bursa.BLSPublicKeySize)
	require.Len(t, decoded[1], bursa.BLSPossessionProofSize)
}
