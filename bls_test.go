// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package bursa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestBLSKeyDeterministicVector(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x42}, BLSSecretKeySize)
	key, err := NewBLSKeyFromIKM(ikm)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(key.PublicKey), "981e7e992ab88b62afe0c27c006af90d43bc42300eef15c21c50198cb8c389e11b4de7e282076868eb18ba5b520a2819153062abf515f2a7e593d180dec9ec2ed74fcd0dbb884743e61c4afb3ae6eb3356030c299de34fac5b62672b12aa745c"; got != want {
		t.Fatalf("public key = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(key.PossessionProof), "90798ee2d044031096d849936f4302c841b37c6d4d737e451f65bb07313b56508ab89f5a8e2b77248c2d2404a11c6e52"; got != want {
		t.Fatalf("possession proof = %s, want %s", got, want)
	}
	if len(key.PublicKey) != BLSPublicKeySize || len(key.PossessionProof) != BLSPossessionProofSize {
		t.Fatal("generated BLS registration material has invalid length")
	}
	if !key.VerifyPossessionProof() {
		t.Fatal("generated proof did not verify")
	}
	keyAgain, err := NewBLSKeyFromIKM(ikm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.PublicKey, keyAgain.PublicKey) || !bytes.Equal(key.PossessionProof, keyAgain.PossessionProof) {
		t.Fatal("same BLS keygen input produced different output")
	}
}

func TestBLSKeyRejectsInvalidProof(t *testing.T) {
	key, err := NewBLSKeyFromIKM(bytes.Repeat([]byte{0x42}, BLSSecretKeySize))
	if err != nil {
		t.Fatal(err)
	}
	key.PossessionProof[0] ^= 1
	if key.VerifyPossessionProof() {
		t.Fatal("invalid proof was accepted")
	}
	key.PossessionProof = key.PossessionProof[:len(key.PossessionProof)-1]
	if key.VerifyPossessionProof() {
		t.Fatal("short proof was accepted")
	}
}

func TestBLSKeyRejectsInfinityPoints(t *testing.T) {
	key, err := NewBLSKeyFromIKM(bytes.Repeat([]byte{0x42}, BLSSecretKeySize))
	if err != nil {
		t.Fatal(err)
	}
	key.PublicKey = append([]byte{0xc0}, make([]byte, BLSPublicKeySize-1)...)
	if key.VerifyPossessionProof() {
		t.Fatal("infinity public key was accepted")
	}

	key, err = NewBLSKeyFromIKM(bytes.Repeat([]byte{0x42}, BLSSecretKeySize))
	if err != nil {
		t.Fatal(err)
	}
	key.PossessionProof = append([]byte{0xc0}, make([]byte, BLSPossessionProofSize-1)...)
	if key.VerifyPossessionProof() {
		t.Fatal("infinity possession proof was accepted")
	}
}

func TestNewBLSKeyFromIKMRejectsShortInput(t *testing.T) {
	if _, err := NewBLSKeyFromIKM(make([]byte, BLSSecretKeySize-1)); err == nil {
		t.Fatal("short keygen input was accepted")
	}
}

func TestBLSEnvelopesValidateMaterial(t *testing.T) {
	key, err := NewBLSKeyFromIKM(bytes.Repeat([]byte{0x42}, BLSSecretKeySize))
	if err != nil {
		t.Fatal(err)
	}

	invalidSecret := &BLSKey{SecretKey: make([]byte, BLSSecretKeySize)}
	if _, err := invalidSecret.BLSKeyEnvelope(); err == nil {
		t.Fatal("zero BLS secret scalar was accepted")
	}
	invalidSecret.SecretKey = bytes.Repeat([]byte{0xff}, BLSSecretKeySize)
	if _, err := invalidSecret.BLSKeyEnvelope(); err == nil {
		t.Fatal("out-of-range BLS secret scalar was accepted")
	}

	invalidPublic := &BLSKey{PublicKey: append([]byte{0xc0}, make([]byte, BLSPublicKeySize-1)...)}
	if _, err := invalidPublic.BLSVerificationKeyEnvelope(); err == nil {
		t.Fatal("infinity BLS public key was accepted")
	}

	for _, envelope := range []KeyFile{
		mustBLSKeyEnvelope(t, key),
		mustBLSVerificationKeyEnvelope(t, key),
	} {
		data, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadKeyFromBytes(data)
		if err != nil {
			t.Fatalf("load %s envelope: %v", envelope.Type, err)
		}
		if len(loaded.VKey) == 0 {
			t.Fatalf("load %s envelope returned no public key", envelope.Type)
		}
	}
}

func mustBLSKeyEnvelope(t *testing.T, key *BLSKey) KeyFile {
	t.Helper()
	envelope, err := key.BLSKeyEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func mustBLSVerificationKeyEnvelope(t *testing.T, key *BLSKey) KeyFile {
	t.Helper()
	envelope, err := key.BLSVerificationKeyEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
