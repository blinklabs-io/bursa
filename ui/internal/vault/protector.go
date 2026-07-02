// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vault

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/ui/internal/keystore"
)

// vekLen is the length of the Vault Encryption Key: a per-vault random 32-byte
// (AES-256) key that actually drives the index blob's encryption. The VEK is
// itself wrapped by a KeyProtector and stored in the envelope's key section, so
// the password (and, in a later task, a TPM) guard only this one small key
// rather than encrypting the wallet data directly.
const vekLen = 32

// KeyProtector wraps (and unwraps) the Vault Encryption Key. It is the seam that
// lets the VEK be guarded by a password today and, without changing any caller,
// by a TPM (or a non-TPM stub) in a later task. Each protector serializes the
// wrapped VEK into a keystore.Container — the same self-describing blob the rest
// of the vault uses — so the envelope's key section is uniform across protectors.
type KeyProtector interface {
	// Wrap encrypts vek (guarded by password) into a Container for at-rest
	// storage in the envelope.
	Wrap(vek []byte, password string) (keystore.Container, error)
	// Unwrap recovers the VEK from a Container produced by Wrap, authenticating
	// with password. A wrong password returns ErrWrongPassword.
	Unwrap(blob keystore.Container, password string) ([]byte, error)
	// Available reports whether this protector can be used in the current
	// environment, with a human-readable reason when it cannot. The password
	// protector is always available; a TPM protector reports availability from a
	// device probe.
	Available() (bool, string)
}

// passwordProtector wraps the VEK with AES-256-GCM under a scrypt(password) key,
// reusing the keystore's Seal/Open primitives — the exact at-rest scheme the
// vault already uses, so no new crypto is introduced. It holds the injectable
// seal/open functions so tests can swap in a cheap KDF (matching Vault.SetCipher)
// while production keeps the full-cost scrypt.
type passwordProtector struct {
	seal keystore.Sealer
	open keystore.Opener
}

// newPasswordProtector returns a passwordProtector using the given seal/open
// primitives (production: keystore.Seal/Open; tests: keystore.CheapTestSealer).
func newPasswordProtector(seal keystore.Sealer, open keystore.Opener) *passwordProtector {
	return &passwordProtector{seal: seal, open: open}
}

// Wrap seals the VEK under password into a Container.
func (p *passwordProtector) Wrap(vek []byte, password string) (keystore.Container, error) {
	if len(vek) != vekLen {
		return keystore.Container{}, fmt.Errorf("vault: VEK must be %d bytes, got %d", vekLen, len(vek))
	}
	blob, err := p.seal(vek, password)
	if err != nil {
		return keystore.Container{}, err
	}
	var c keystore.Container
	if err := json.Unmarshal(blob, &c); err != nil {
		return keystore.Container{}, err
	}
	return c, nil
}

// Unwrap recovers the VEK from blob, authenticating with password. A wrong
// password (AES-GCM authentication failure) maps to ErrWrongPassword.
func (p *passwordProtector) Unwrap(blob keystore.Container, password string) ([]byte, error) {
	raw, err := json.Marshal(blob)
	if err != nil {
		return nil, err
	}
	vek, err := p.open(raw, []byte(password))
	if err != nil {
		if errors.Is(err, keystore.ErrDecryptFailed) {
			return nil, fmt.Errorf("%w: %w", ErrWrongPassword, err)
		}
		return nil, err
	}
	// Fail closed on a corrupt/non-conforming blob: a wrong-length VEK would
	// otherwise unlock here and only fail later when the vault is re-persisted.
	if len(vek) != vekLen {
		return nil, fmt.Errorf("vault: unwrapped VEK has length %d, want %d", len(vek), vekLen)
	}
	return vek, nil
}

// Available always reports true: the password protector needs no special
// hardware and is the universal fallback path.
func (p *passwordProtector) Available() (bool, string) {
	return true, ""
}
