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

package backend

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// coseTagSign1 is the optional CBOR tag in front of a COSE_Sign1 message.
const coseTagSign1 = 0xd2

// coseAlgES384 is the COSE algorithm identifier for ECDSA with SHA-384.
const coseAlgES384 = -35

// nitroPCRSize is the length in bytes of a SHA-384 PCR value.
const nitroPCRSize = 48

// NitroVerifier validates AWS Nitro Enclaves attestation documents against a
// pinned root certificate and expected PCR values.
type NitroVerifier struct {
	roots *x509.CertPool
	// pcrs maps a PCR index to its required value. PCR0 (the enclave image
	// measurement) is mandatory.
	pcrs map[uint][]byte
	now  func() time.Time
}

// NewNitroVerifier builds a verifier. rootsPEM is the AWS Nitro root
// certificate; pcrs maps PCR indexes to their required 48-byte values and must
// include PCR0 with a non-zero value, which excludes debug-mode enclaves (the
// platform reports every PCR as zero for those).
func NewNitroVerifier(rootsPEM []byte, pcrs map[uint][]byte) (*NitroVerifier, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return nil, errors.New("nitro root certificate: no PEM certificate found")
	}
	pcr0, ok := pcrs[0]
	if !ok {
		return nil, errors.New("nitro verifier requires an expected PCR0")
	}
	for i, v := range pcrs {
		if len(v) != nitroPCRSize {
			return nil, fmt.Errorf("expected PCR%d must be %d bytes, got %d", i, nitroPCRSize, len(v))
		}
	}
	if bytes.Equal(pcr0, make([]byte, nitroPCRSize)) {
		return nil, errors.New("expected PCR0 is all zeros (a debug-mode measurement)")
	}
	return &NitroVerifier{roots: roots, pcrs: pcrs, now: time.Now}, nil
}

type coseSign1Msg struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type nitroDocument struct {
	Digest      string          `cbor:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs"`
	Certificate []byte          `cbor:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle"`
	UserData    []byte          `cbor:"user_data"`
}

// Verify implements AttestationVerifier. The document's user_data must equal
// binding.
func (v *NitroVerifier) Verify(_ context.Context, evidence, binding []byte) error {
	evidence = bytes.TrimPrefix(evidence, []byte{coseTagSign1})
	var msg coseSign1Msg
	if err := cbor.Unmarshal(evidence, &msg); err != nil {
		return fmt.Errorf("nitro document: %w", err)
	}
	var protected map[int]int
	if err := cbor.Unmarshal(msg.Protected, &protected); err != nil {
		return fmt.Errorf("nitro protected header: %w", err)
	}
	if protected[1] != coseAlgES384 {
		return fmt.Errorf("nitro document: unsupported COSE algorithm %d", protected[1])
	}
	var doc nitroDocument
	if err := cbor.Unmarshal(msg.Payload, &doc); err != nil {
		return fmt.Errorf("nitro payload: %w", err)
	}
	if doc.Digest != "SHA384" {
		return fmt.Errorf("nitro document: unsupported digest %q", doc.Digest)
	}

	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return fmt.Errorf("nitro leaf certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range doc.CABundle {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("nitro cabundle certificate: %w", err)
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("nitro certificate chain: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("nitro leaf certificate key is not ECDSA")
	}
	if len(msg.Signature) != 96 {
		return fmt.Errorf("nitro signature must be 96 bytes, got %d", len(msg.Signature))
	}
	toBeSigned, err := cbor.Marshal([]any{"Signature1", msg.Protected, []byte{}, msg.Payload})
	if err != nil {
		return fmt.Errorf("nitro sig structure: %w", err)
	}
	digest := sha512.Sum384(toBeSigned)
	r := new(big.Int).SetBytes(msg.Signature[:48])
	s := new(big.Int).SetBytes(msg.Signature[48:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("nitro document signature invalid")
	}

	for idx, want := range v.pcrs {
		if subtle.ConstantTimeCompare(doc.PCRs[idx], want) != 1 {
			return fmt.Errorf("nitro PCR%d does not match the expected measurement", idx)
		}
	}
	if subtle.ConstantTimeCompare(doc.UserData, binding) != 1 {
		return errors.New("nitro document user_data does not match the attestation binding")
	}
	return nil
}
