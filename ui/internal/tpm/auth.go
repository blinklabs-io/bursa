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

package tpm

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	authSaltLen = 16
	authKeyLen  = 32

	authScryptN = 1 << 15
	authScryptR = 8
	authScryptP = 1
)

func newAuthSalt() ([]byte, error) {
	salt := make([]byte, authSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func authValue(password string, salt []byte) ([]byte, error) {
	if len(salt) != authSaltLen {
		return nil, fmt.Errorf("tpm: auth salt must be %d bytes, got %d", authSaltLen, len(salt))
	}
	auth, err := scrypt.Key([]byte(password), salt, authScryptN, authScryptR, authScryptP, authKeyLen)
	if err != nil {
		return nil, fmt.Errorf("tpm: derive auth value: %w", err)
	}
	return auth, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
