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

package confidentialspace

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// envelopeVersionKeys is the multi-key envelope: one pool cold key per
// profile under a single KMS-wrapped data-encryption key. It is written only
// by an import, is always active, and is never replaced. The wrapped key's
// additional data covers the whole profile-to-public-key map, and each seed's
// additional data covers its profile, so neither a profile's key nor the map
// can be changed without the unwrap or the open failing.
const envelopeVersionKeys = "bursa-confidential-space-key/3"

// envelopeKey is one profile's key in a multi-key envelope.
type envelopeKey struct {
	Profile    string `json:"profile"`
	PublicKey  []byte `json:"public_key"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func (e envelope) multiKey() bool { return e.Version == envelopeVersionKeys }

// validateEnvelopeKeys checks the shape of a multi-key envelope's keys: 1 to
// maxImportProfiles sorted distinct profiles with distinct public keys, and
// no top-level key. keySealed also requires the wrapped data-encryption key
// and each sealed seed to be present.
func validateEnvelopeKeys(e envelope, keySealed bool) error {
	if len(e.PublicKey) != 0 || len(e.Nonce) != 0 || len(e.Ciphertext) != 0 ||
		(keySealed && len(e.WrappedDEK) == 0) || len(e.Keys) == 0 ||
		len(e.Keys) > maxImportProfiles {
		return errors.New("wrapped key is incomplete")
	}
	for n, k := range e.Keys {
		if ValidateProfile(k.Profile) != nil ||
			len(k.PublicKey) != ed25519.PublicKeySize {
			return errors.New("wrapped key is incomplete")
		}
		if keySealed && (len(k.Nonce) == 0 || len(k.Ciphertext) == 0) {
			return errors.New("wrapped key is incomplete")
		}
		if n > 0 && e.Keys[n-1].Profile >= k.Profile {
			return errors.New("wrapped key profiles must be sorted and distinct")
		}
		for _, prev := range e.Keys[:n] {
			if slices.Equal(prev.PublicKey, k.PublicKey) {
				return errors.New("wrapped key holds one key under two profiles")
			}
		}
	}
	return nil
}

// envelopeKeyAAD is the additional data of one profile's sealed seed.
func envelopeKeyAAD(e envelope, profile string) []byte {
	aad := envelopeAAD(e)
	var size [4]byte
	// #nosec G115 -- a profile name is at most maxProfileLength bytes.
	binary.BigEndian.PutUint32(size[:], uint32(len(profile)))
	aad = append(aad, size[:]...)
	return append(aad, profile...)
}

// openEnvelopeKeys decrypts every profile's seed of a multi-key envelope.
func openEnvelopeKeys(
	e envelope,
	gcm cipher.AEAD,
) (map[string]ed25519.PrivateKey, error) {
	privs := make(map[string]ed25519.PrivateKey, len(e.Keys))
	wipeAll := func() {
		for _, priv := range privs {
			wipe(priv)
		}
	}
	for _, k := range e.Keys {
		if len(k.Nonce) != gcm.NonceSize() {
			wipeAll()
			return nil, errors.New("wrapped key nonce has invalid length")
		}
		seed, err := gcm.Open(
			nil, k.Nonce, k.Ciphertext, envelopeKeyAAD(e, k.Profile),
		)
		if err != nil {
			wipeAll()
			return nil, errors.New("decrypt wrapped key")
		}
		if len(seed) != ed25519.SeedSize {
			wipe(seed)
			wipeAll()
			return nil, errors.New("wrapped pool key has invalid length")
		}
		priv := ed25519.NewKeyFromSeed(seed)
		wipe(seed)
		if !ed25519.PublicKey(priv.Public().(ed25519.PublicKey)).
			Equal(ed25519.PublicKey(k.PublicKey)) {
			wipe(priv)
			wipeAll()
			return nil, errors.New(
				"wrapped key public key does not match plaintext",
			)
		}
		privs[k.Profile] = priv
	}
	return privs, nil
}

// wrapSeeds envelope-encrypts one Ed25519 seed per profile under a fresh
// data-encryption key that Cloud KMS wraps, into an active multi-key
// envelope. An import passes the seeds the operator supplied; no key is ever
// generated here. The caller wipes seeds.
func wrapSeeds(
	ctx context.Context,
	cfg Config,
	seeds map[string][]byte,
) (*keyMaterial, error) {
	profiles := make([]string, 0, len(seeds))
	for profile := range seeds {
		profiles = append(profiles, profile)
	}
	slices.Sort(profiles)
	privs := make(map[string]ed25519.PrivateKey, len(seeds))
	material := &keyMaterial{profileKeys: privs}
	e := envelope{
		Version: envelopeVersionKeys,
		Phase:   envelopeActive,
		Role:    backend.KeyTypePool,
		KMSKey:  cfg.KMSKey,
	}
	for _, profile := range profiles {
		if len(seeds[profile]) != ed25519.SeedSize {
			material.wipe()
			return nil, errors.New("pool key seed has invalid length")
		}
		priv := ed25519.NewKeyFromSeed(seeds[profile])
		privs[profile] = priv
		e.Keys = append(e.Keys, envelopeKey{
			Profile: profile,
			PublicKey: append(
				[]byte(nil), priv.Public().(ed25519.PublicKey)...,
			),
		})
	}
	if err := validateEnvelopeKeys(e, false); err != nil {
		material.wipe()
		return nil, err
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		material.wipe()
		return nil, fmt.Errorf("generate data-encryption key: %w", err)
	}
	defer wipe(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		material.wipe()
		return nil, fmt.Errorf("initialize envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		material.wipe()
		return nil, fmt.Errorf("initialize envelope AEAD: %w", err)
	}
	for n := range e.Keys {
		k := &e.Keys[n]
		k.Nonce = make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, k.Nonce); err != nil {
			material.wipe()
			return nil, fmt.Errorf("generate envelope nonce: %w", err)
		}
		k.Ciphertext = gcm.Seal(
			nil, k.Nonce, seeds[k.Profile], envelopeKeyAAD(e, k.Profile),
		)
	}
	wrapped, err := cfg.Wrapper.Wrap(ctx, dek, envelopeAAD(e))
	if err != nil {
		material.wipe()
		return nil, fmt.Errorf("wrap data-encryption key: %w", err)
	}
	e.WrappedDEK = wrapped
	data, err := json.Marshal(e)
	if err != nil {
		material.wipe()
		return nil, fmt.Errorf("encode wrapped key: %w", err)
	}
	material.stored, material.active = data, data
	return material, nil
}
