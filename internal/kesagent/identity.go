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

package kesagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
)

const (
	// IdentityKeyProvider is the attestation provider name for evidence signed
	// by a pinned Ed25519 identity key instead of platform measurement.
	IdentityKeyProvider = "identity-key"
	// IdentityKeyFileType is the text-envelope type of an identity key file.
	IdentityKeyFileType = "KESAgentIdentitySigningKey_ed25519"
)

// IdentityKeyAttester signs the attestation binding with the agent's identity
// key. The evidence proves the response came from a holder of that key; it is
// not a measurement of the workload.
type IdentityKeyAttester struct {
	key ed25519.PrivateKey
}

// NewIdentityKeyAttester takes ownership of a copy of key.
func NewIdentityKeyAttester(
	key ed25519.PrivateKey,
) (*IdentityKeyAttester, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"kesagent: identity key must be %d bytes, got %d",
			ed25519.PrivateKeySize,
			len(key),
		)
	}
	return &IdentityKeyAttester{key: bytes.Clone(key)}, nil
}

// Evidence implements Attester. binding must be an AttestationBinding digest.
func (a *IdentityKeyAttester) Evidence(
	_ context.Context,
	binding []byte,
) ([]byte, error) {
	if len(binding) != sha256.Size {
		return nil, errors.New("kesagent: identity key binding is not a digest")
	}
	return ed25519.Sign(a.key, binding), nil
}

// IdentityKeyVerifier checks identity-key evidence against a pinned public
// key. A client passes it to VerifyAttestation.
type IdentityKeyVerifier struct {
	identity ed25519.PublicKey
}

// NewIdentityKeyVerifier pins the agent's identity public key.
func NewIdentityKeyVerifier(
	identity ed25519.PublicKey,
) (*IdentityKeyVerifier, error) {
	if len(identity) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"kesagent: identity public key must be %d bytes, got %d",
			ed25519.PublicKeySize,
			len(identity),
		)
	}
	if bytes.Equal(identity, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New("kesagent: identity public key is all zeros")
	}
	return &IdentityKeyVerifier{identity: bytes.Clone(identity)}, nil
}

// Verify implements AttestationVerifier.
func (v *IdentityKeyVerifier) Verify(
	_ context.Context,
	evidence, binding []byte,
) error {
	if len(evidence) != ed25519.SignatureSize ||
		!ed25519.Verify(v.identity, binding, evidence) {
		return errors.New(
			"kesagent: binding is not signed by the pinned identity key",
		)
	}
	return nil
}

// LoadIdentityKey reads an identity signing key file: a text envelope of type
// IdentityKeyFileType whose cborHex is a CBOR byte string holding the 32-byte
// Ed25519 seed. The file must not be readable by others.
func LoadIdentityKey(path string) (ed25519.PrivateKey, error) {
	data, err := bursa.ReadSecretKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var env struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, errors.New("identity key file is not a text envelope")
	}
	if env.Type != IdentityKeyFileType {
		return nil, fmt.Errorf(
			"identity key envelope type %q, want %q",
			env.Type,
			IdentityKeyFileType,
		)
	}
	raw, err := hex.DecodeString(env.CborHex)
	defer clear(raw)
	if err != nil || len(raw) != 2+ed25519.SeedSize || raw[0] != 0x58 ||
		raw[1] != ed25519.SeedSize {
		return nil, errors.New("identity key cborHex is not a 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(raw[2:]), nil
}
