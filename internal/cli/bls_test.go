// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
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
