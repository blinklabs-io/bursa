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
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ArmoryVerifier checks a USB armory inventory against the device identity
// key pinned in configuration. The evidence is the identity key's Ed25519
// signature over the inventory binding. It proves the inventory came from a
// device holding that key; it is not a measurement of the firmware.
type ArmoryVerifier struct {
	identity ed25519.PublicKey
}

// NewArmoryVerifier pins the device identity public key.
func NewArmoryVerifier(identity ed25519.PublicKey) (*ArmoryVerifier, error) {
	if len(identity) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("armory identity key must be %d bytes, got %d", ed25519.PublicKeySize, len(identity))
	}
	if bytes.Equal(identity, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New("armory identity key is all zeros")
	}
	return &ArmoryVerifier{identity: bytes.Clone(identity)}, nil
}

// Verify implements AttestationVerifier.
func (v *ArmoryVerifier) Verify(_ context.Context, evidence, binding []byte) error {
	if len(evidence) != ed25519.SignatureSize || !ed25519.Verify(v.identity, binding, evidence) {
		return errors.New("armory inventory is not signed by the pinned identity key")
	}
	return nil
}
