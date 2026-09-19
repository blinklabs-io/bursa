// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package bursa

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/blinklabs-io/gouroboros/cbor"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"golang.org/x/crypto/hkdf"
)

const (
	BLSSecretKeySize       = 32
	BLSPublicKeySize       = 96
	BLSPossessionProofSize = 48

	// This is the draft-06 proof-of-possession DST for BLS12-381 MinSig.
	// MinSig public keys are encoded in G2, while the PoP is encoded in G1.
	BLSProofOfPossessionDST = "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
)

var errInvalidBLSSecretKey = errors.New("invalid BLS secret key")

// BLSKey contains the private key and registration material for a Dijkstra-era
// stake-pool key used by protocols such as Leios and Peras.
type BLSKey struct {
	SecretKey       []byte
	PublicKey       []byte
	PossessionProof []byte
}

// NewBLSKey creates a key from cryptographically secure random input.
func NewBLSKey() (*BLSKey, error) {
	ikm := make([]byte, BLSSecretKeySize)
	if _, err := rand.Read(ikm); err != nil {
		return nil, fmt.Errorf("generate BLS secret key: %w", err)
	}
	return NewBLSKeyFromIKM(ikm)
}

// NewBLSKeyFromIKM derives a key deterministically from BLS keygen input.
// It is intended for test vectors and controlled key import, not passphrases.
func NewBLSKeyFromIKM(ikm []byte) (*BLSKey, error) {
	if len(ikm) < BLSSecretKeySize {
		return nil, fmt.Errorf("BLS keygen input must be at least %d bytes", BLSSecretKeySize)
	}
	secret, err := blsKeyGen(ikm)
	if err != nil {
		return nil, err
	}
	sk := new(big.Int).SetBytes(secret)
	var publicPoint bls12381.G2Jac
	publicPoint.ScalarMultiplicationBase(sk)
	var publicAffine bls12381.G2Affine
	publicAffine.FromJacobian(&publicPoint)
	publicBytes := publicAffine.Bytes()
	public := append([]byte(nil), publicBytes[:]...)
	hashPoint, err := bls12381.HashToG1(public, []byte(BLSProofOfPossessionDST))
	if err != nil {
		return nil, fmt.Errorf("hash BLS public key for proof: %w", err)
	}
	var hashJac bls12381.G1Jac
	hashJac.FromAffine(&hashPoint)
	var proofPoint bls12381.G1Jac
	proofPoint.ScalarMultiplication(&hashJac, sk)
	var proofAffine bls12381.G1Affine
	proofAffine.FromJacobian(&proofPoint)
	proofBytes := proofAffine.Bytes()
	proof := append([]byte(nil), proofBytes[:]...)
	if len(public) != BLSPublicKeySize || len(proof) != BLSPossessionProofSize {
		return nil, errors.New("BLS library returned an invalid key size")
	}
	key := &BLSKey{SecretKey: secret, PublicKey: public, PossessionProof: proof}
	if !key.VerifyPossessionProof() {
		return nil, errors.New("generated BLS possession proof failed verification")
	}
	return key, nil
}

// VerifyPossessionProof verifies the proof against this key's public key.
func (k *BLSKey) VerifyPossessionProof() bool {
	if k == nil || len(k.PublicKey) != BLSPublicKeySize || len(k.PossessionProof) != BLSPossessionProofSize {
		return false
	}
	var pk bls12381.G2Affine
	if n, err := pk.SetBytes(k.PublicKey); err != nil || n != len(k.PublicKey) || !pk.IsInSubGroup() {
		return false
	}
	var proof bls12381.G1Affine
	if n, err := proof.SetBytes(k.PossessionProof); err != nil || n != len(k.PossessionProof) || !proof.IsInSubGroup() {
		return false
	}
	hashPoint, err := bls12381.HashToG1(k.PublicKey, []byte(BLSProofOfPossessionDST))
	if err != nil {
		return false
	}
	_, _, _, generator := bls12381.Generators()
	var negPK bls12381.G2Affine
	negPK.Neg(&pk)
	valid, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{proof, hashPoint},
		[]bls12381.G2Affine{generator, negPK},
	)
	return err == nil && valid
}

func blsKeyGen(ikm []byte) ([]byte, error) {
	const keyGenSalt = "BLS-SIG-KEYGEN-SALT-"
	const outputLength = 48
	salt := []byte(keyGenSalt)
	for {
		hash := sha256.Sum256(salt)
		salt = hash[:]
		input := append(append([]byte(nil), ikm...), 0)
		reader := hkdf.New(sha256.New, input, salt, []byte{0, outputLength})
		okm := make([]byte, outputLength)
		if _, err := io.ReadFull(reader, okm); err != nil {
			return nil, fmt.Errorf("derive BLS secret key: %w", err)
		}
		sk := new(big.Int).Mod(new(big.Int).SetBytes(okm), fr.Modulus())
		if sk.Sign() != 0 {
			out := sk.FillBytes(make([]byte, BLSSecretKeySize))
			return out, nil
		}
		hash = sha256.Sum256(salt)
		salt = hash[:]
	}
}

// BLSKeyEnvelope returns the cardano-cli signing-key envelope.
func (k *BLSKey) BLSKeyEnvelope() (KeyFile, error) {
	if k == nil || len(k.SecretKey) != BLSSecretKeySize {
		return KeyFile{}, errInvalidBLSSecretKey
	}
	cborHex, err := cbor.Encode(k.SecretKey)
	if err != nil {
		return KeyFile{}, fmt.Errorf("encode BLS secret key: %w", err)
	}
	return KeyFile{Type: "BlsSigningKey", Description: "BLS signing key", CborHex: fmt.Sprintf("%x", cborHex)}, nil
}

// BLSVerificationKeyEnvelope returns a cardano-cli verification-key envelope.
func (k *BLSKey) BLSVerificationKeyEnvelope() (KeyFile, error) {
	if k == nil || len(k.PublicKey) != BLSPublicKeySize {
		return KeyFile{}, errors.New("invalid BLS public key")
	}
	cborHex, err := cbor.Encode(k.PublicKey)
	if err != nil {
		return KeyFile{}, fmt.Errorf("encode BLS public key: %w", err)
	}
	return KeyFile{Type: "BlsVerificationKey", Description: "BLS verification key", CborHex: fmt.Sprintf("%x", cborHex)}, nil
}
