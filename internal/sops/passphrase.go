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

package sops

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

type passphraseContainer struct {
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

const (
	scryptN     = 32768
	scryptR     = 8
	scryptP     = 1
	gcmNonceLen = 12
	keyLen      = 32
)

// EncryptWithPassphrase encrypts data with a passphrase using scrypt + AES-256-GCM
// and returns a self-describing JSON container.
func EncryptWithPassphrase(data []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase must not be empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keyLen)
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
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, data, nil)
	return json.Marshal(passphraseContainer{
		KDF: "scrypt", N: scryptN, R: scryptR, P: scryptP,
		Salt: hex.EncodeToString(salt), Nonce: hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	})
}

// DecryptWithPassphrase reverses EncryptWithPassphrase.
func DecryptWithPassphrase(data []byte, passphrase string) ([]byte, error) {
	var c passphraseContainer
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("not a passphrase container: %w", err)
	}
	if c.KDF != "scrypt" {
		return nil, fmt.Errorf("unsupported kdf %q", c.KDF)
	}
	if c.N != scryptN || c.R != scryptR || c.P != scryptP {
		return nil, fmt.Errorf(
			"unsupported scrypt parameters n=%d r=%d p=%d",
			c.N,
			c.R,
			c.P,
		)
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
		return nil, fmt.Errorf(
			"invalid nonce length %d, expected %d",
			len(nonce),
			gcmNonceLen,
		)
	}
	ct, err := hex.DecodeString(c.Ciphertext)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, c.N, c.R, c.P, keyLen)
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
		return nil, errors.New("decryption failed (wrong passphrase or corrupt data)")
	}
	return pt, nil
}

// IsPassphraseContainer reports whether data looks like a passphrase container.
func IsPassphraseContainer(data []byte) bool {
	var c passphraseContainer
	return json.Unmarshal(data, &c) == nil && c.KDF == "scrypt" && c.Ciphertext != ""
}

// IsEncrypted reports whether data is a SOPS-encrypted JSON document (top-level
// "sops" metadata key). Used by the file store to decide whether to decrypt.
func IsEncrypted(data []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil {
		return false
	}
	_, ok := m["sops"]
	return ok
}
