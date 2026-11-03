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

package device

import (
	"crypto/ed25519"
	"fmt"
)

// RawSignKeyID holds the key the testnet bring-up build's unfiltered /sign
// signs with. It lies in the bring-up object range, outside the cold key
// range every profile can occupy, so no profile key can be used through it.
const RawSignKeyID uint32 = 0x20e50003

// rawSignRole names the raw signing key in signing log entries.
const rawSignRole = "raw"

// RawChip is the SE050 subset the unfiltered signature needs.
type RawChip interface {
	Exists(id uint32) (bool, error)
	GenerateEd25519(id uint32, transient bool) error
	PublicKeyEd25519(id uint32) (ed25519.PublicKey, error)
	SignEd25519(id uint32, msg []byte) ([]byte, error)
}

// ensureRawKey generates the raw signing key when it is absent.
func ensureRawKey(chip RawChip) error {
	ok, err := chip.Exists(RawSignKeyID)
	if err != nil {
		return fmt.Errorf("exist check: %w", err)
	}

	if ok {
		return nil
	}

	if err = chip.GenerateEd25519(RawSignKeyID, false); err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	return nil
}

// SignRaw signs msg with the raw signing key, generating the key on first use.
// It never touches a cold key or a profile key.
func SignRaw(chip RawChip, msg []byte) ([]byte, error) {
	if err := ensureRawKey(chip); err != nil {
		return nil, err
	}

	return chip.SignEd25519(RawSignKeyID, msg)
}

// RawPublicKey returns the raw signing key's public key, generating the key
// on first use.
func RawPublicKey(chip RawChip) (ed25519.PublicKey, error) {
	if err := ensureRawKey(chip); err != nil {
		return nil, err
	}

	return chip.PublicKeyEd25519(RawSignKeyID)
}
