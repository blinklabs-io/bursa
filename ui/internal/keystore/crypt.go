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

package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// Container is a self-describing scrypt + AES-256-GCM encrypted blob. It is the
// exact at-rest scheme the wallet keystore uses for the mnemonic; it is exported
// so the vault can reuse it to encrypt its index under the vault password,
// rather than inventing a second crypto scheme. The fields carry the KDF cost so
// it can be raised in a future release without a format break.
type Container struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// container is the unexported alias used by keystore.go's mnemonic file. It is
// the same shape as Container; both share the encrypt/decrypt helpers below.
type container = Container

// encrypt seals plaintext under password using scrypt (cost kdf) + AES-256-GCM,
// returning a self-describing Container. This is the single encrypt primitive
// reused by both the mnemonic keystore and the vault index.
func encrypt(plaintext []byte, password string, kdf kdfParams) (Container, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return Container{}, err
	}
	key, err := scrypt.Key([]byte(password), salt, kdf.n, kdf.r, kdf.p, keyLen)
	if err != nil {
		return Container{}, fmt.Errorf("scrypt: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Container{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Container{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Container{}, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return Container{
		Version: containerVersion,
		KDF:     "scrypt", N: kdf.n, R: kdf.r, P: kdf.p,
		Salt: hex.EncodeToString(salt), Nonce: hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	}, nil
}

// decrypt authenticates and opens a Container with password, accepting only KDF
// params within the allowed range. A wrong password or tampered blob returns
// ErrDecryptFailed (AES-GCM authentication). Callers should Zero the returned
// bytes once the plaintext is no longer needed.
func decrypt(c Container, password string, kdf kdfParams) ([]byte, error) {
	if c.Version != containerVersion {
		return nil, fmt.Errorf("unsupported container version %d", c.Version)
	}
	if c.KDF != "scrypt" ||
		c.N < kdf.minN || c.N > kdf.maxN ||
		c.R < kdf.minR || c.R > kdf.maxR ||
		c.P < kdf.minP || c.P > kdf.maxP {
		return nil, fmt.Errorf("unsupported KDF params (kdf=%q n=%d r=%d p=%d)", c.KDF, c.N, c.R, c.P)
	}
	salt, err := hex.DecodeString(c.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(c.Nonce)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcmNonceLen {
		return nil, fmt.Errorf("invalid nonce length %d", len(nonce))
	}
	ct, err := hex.DecodeString(c.Ciphertext)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(password), salt, c.N, c.R, c.P, keyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: wrong password or corrupt container", ErrDecryptFailed)
	}
	return pt, nil
}

// Seal encrypts plaintext under password at the production KDF cost and returns
// the JSON encoding of the resulting Container. It is the reusable counterpart
// to Keystore.Create, for callers (the vault) that manage their own file I/O.
// password must be at least MinPasswordLen runes; the caller is responsible for
// enforcing that floor before reaching here (the API does).
func Seal(plaintext []byte, password string) ([]byte, error) {
	c, err := encrypt(plaintext, password, productionKDF)
	if err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// Open decrypts a JSON Container blob produced by Seal with password, accepting
// production-range KDF params. A wrong password or tampered blob returns
// ErrDecryptFailed.
func Open(blob, password []byte) ([]byte, error) {
	var c Container
	if err := json.Unmarshal(blob, &c); err != nil {
		return nil, fmt.Errorf("not a container: %w", err)
	}
	return decrypt(c, string(password), productionKDF)
}

// Sealer seals plaintext under password into a JSON Container blob; Opener is
// its inverse. The vault accepts these as injectable functions so its tests can
// swap in a cheap KDF, while production uses Seal/Open (full scrypt cost).
type (
	Sealer func(plaintext []byte, password string) ([]byte, error)
	Opener func(blob, password []byte) ([]byte, error)
)

// CheapTestSealer returns a Sealer/Opener pair using a deliberately cheap scrypt
// cost (~4 MiB, sub-millisecond), for tests of packages that build on Seal/Open
// (e.g. the vault) without paying the ~1 s production KDF per call. It must
// never be used outside tests.
func CheapTestSealer() (Sealer, Opener) {
	cheap := kdfParams{
		n: 1 << 12, r: 8, p: 1,
		minN: 1 << 12, maxN: 1 << 14,
		minR: 8, maxR: 32,
		minP: 1, maxP: 4,
	}
	seal := func(plaintext []byte, password string) ([]byte, error) {
		c, err := encrypt(plaintext, password, cheap)
		if err != nil {
			return nil, err
		}
		return json.Marshal(c)
	}
	open := func(blob, password []byte) ([]byte, error) {
		var c Container
		if err := json.Unmarshal(blob, &c); err != nil {
			return nil, fmt.Errorf("not a container: %w", err)
		}
		return decrypt(c, string(password), cheap)
	}
	return seal, open
}
