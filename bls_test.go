// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package bursa

import (
	"bytes"
	"encoding/hex"
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
	if got, want := hex.EncodeToString(key.PossessionProof), "87b2f091cc71ee38de8406bd216260cdc9fe49f76edea1e74faba326d5b0b364e1832b0381ec2ed811434b7cf7d41c81"; got != want {
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

func TestNewBLSKeyFromIKMRejectsShortInput(t *testing.T) {
	if _, err := NewBLSKeyFromIKM(make([]byte, BLSSecretKeySize-1)); err == nil {
		t.Fatal("short keygen input was accepted")
	}
}
