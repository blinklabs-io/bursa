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

package wire

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// StagedKeyAttestationDomain separates a staged-key attestation signature
// from every other signature made with the same identity key, including the
// TLS handshake signatures of the key's certificate.
const StagedKeyAttestationDomain = "bursa-kes-agent-staged-key-v1"

const (
	maxAttestedProfileLen = 256
	maxAttestedSPKILen    = 2048
	maxAttestedSigLen     = 1024
	attestedKESVKeyLen    = 32
	attestedColdHashLen   = 28
)

// Errors returned by StagedKeyAttestation.Verify.
var (
	// ErrStagedKeyAttestationMalformed means a field is missing, the wrong
	// size, or the SPKI is not a supported public key.
	ErrStagedKeyAttestationMalformed = errors.New(
		"malformed staged-key attestation",
	)
	// ErrStagedKeyAttestationSignature means the signature does not verify
	// over the attested fields under the attestation's SPKI.
	ErrStagedKeyAttestationSignature = errors.New(
		"staged-key attestation signature does not verify",
	)
)

// StagedKeyAttestation is an agent's signed statement that it generated KES
// verification key KESVKey in profile Profile, for the pool whose cold
// verification key hashes to ColdKeyHash. SPKI is the DER SubjectPublicKeyInfo
// of the signing identity; a verifier trusts it only after matching its
// SHA-256 against a configured pin.
type StagedKeyAttestation struct {
	Profile     string `json:"profile"`
	KESVKey     []byte `json:"kes_vkey"`
	ColdKeyHash []byte `json:"cold_key_hash"`
	SPKI        []byte `json:"spki"`
	Signature   []byte `json:"signature"`
}

// StagedKeyAttestationMessage is the byte string an attestation signs: the
// domain tag, then each field as a uint64 big-endian length and its bytes.
func StagedKeyAttestationMessage(
	profile string,
	kesVKey, coldKeyHash []byte,
) []byte {
	var out []byte
	out = append(out, StagedKeyAttestationDomain...)
	for _, f := range [][]byte{[]byte(profile), kesVKey, coldKeyHash} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(f)))
		out = append(out, size[:]...)
		out = append(out, f...)
	}
	return out
}

// SignStagedKey attests kesVKey with identity. Ed25519, ECDSA and RSA
// identities are supported, the key types a TLS certificate can carry that
// Verify accepts; ECDSA and RSA sign the SHA-256 of the message.
func SignStagedKey(
	identity crypto.Signer,
	profile string,
	kesVKey, coldKeyHash []byte,
) (*StagedKeyAttestation, error) {
	if identity == nil {
		return nil, errors.New("no attestation identity key")
	}
	spki, err := x509.MarshalPKIXPublicKey(identity.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal attestation public key: %w", err)
	}
	msg := StagedKeyAttestationMessage(profile, kesVKey, coldKeyHash)
	var sig []byte
	switch identity.Public().(type) {
	case ed25519.PublicKey:
		sig, err = identity.Sign(rand.Reader, msg, crypto.Hash(0))
	case *ecdsa.PublicKey, *rsa.PublicKey:
		digest := sha256.Sum256(msg)
		sig, err = identity.Sign(rand.Reader, digest[:], crypto.SHA256)
	default:
		return nil, fmt.Errorf(
			"unsupported attestation key type %T",
			identity.Public(),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("sign staged-key attestation: %w", err)
	}
	return &StagedKeyAttestation{
		Profile:     profile,
		KESVKey:     append([]byte(nil), kesVKey...),
		ColdKeyHash: append([]byte(nil), coldKeyHash...),
		SPKI:        spki,
		Signature:   sig,
	}, nil
}

// SPKISHA256 is the digest a verifier pins for this attestation's identity.
func (a *StagedKeyAttestation) SPKISHA256() [sha256.Size]byte {
	return sha256.Sum256(a.SPKI)
}

// Verify checks the field sizes and the signature under a.SPKI. It does not
// decide whether the identity is trusted, nor whether the attested key,
// pool or profile are the ones wanted; the caller compares those.
func (a *StagedKeyAttestation) Verify() error {
	switch {
	case a == nil:
		return fmt.Errorf("%w: missing", ErrStagedKeyAttestationMalformed)
	case a.Profile == "" || len(a.Profile) > maxAttestedProfileLen:
		return fmt.Errorf("%w: profile", ErrStagedKeyAttestationMalformed)
	case len(a.KESVKey) != attestedKESVKeyLen:
		return fmt.Errorf("%w: kes_vkey must be 32 bytes",
			ErrStagedKeyAttestationMalformed)
	case len(a.ColdKeyHash) != attestedColdHashLen:
		return fmt.Errorf("%w: cold_key_hash must be 28 bytes",
			ErrStagedKeyAttestationMalformed)
	case len(a.SPKI) == 0 || len(a.SPKI) > maxAttestedSPKILen:
		return fmt.Errorf("%w: spki", ErrStagedKeyAttestationMalformed)
	case len(a.Signature) == 0 || len(a.Signature) > maxAttestedSigLen:
		return fmt.Errorf("%w: signature", ErrStagedKeyAttestationMalformed)
	}
	pub, err := x509.ParsePKIXPublicKey(a.SPKI)
	if err != nil {
		return fmt.Errorf("%w: spki: %w", ErrStagedKeyAttestationMalformed, err)
	}
	msg := StagedKeyAttestationMessage(a.Profile, a.KESVKey, a.ColdKeyHash)
	digest := sha256.Sum256(msg)
	var ok bool
	switch k := pub.(type) {
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, msg, a.Signature)
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(k, digest[:], a.Signature)
	case *rsa.PublicKey:
		ok = rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], a.Signature) == nil
	default:
		return fmt.Errorf("%w: unsupported key type %T",
			ErrStagedKeyAttestationMalformed, pub)
	}
	if !ok {
		return ErrStagedKeyAttestationSignature
	}
	return nil
}
