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

package bursa

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPublicKeyEnvelope = `{"type":"PaymentVerificationKeyShelley_ed25519","description":"Payment Verification Key","cborHex":"5820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

func TestLoadKeyFromFileAllowsReadablePublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payment.vkey")
	require.NoError(t, os.WriteFile(path, []byte(testPublicKeyEnvelope), 0o644))

	key, err := LoadKeyFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, filepath.Base(path), key.File)
	assert.Len(t, key.VKey, 32)
	assert.Empty(t, key.SKey)
}

func TestLoadKeyFromFileRejectsOversizedInput(t *testing.T) {
	envelope := `{"type":"PaymentVerificationKeyShelley_ed25519","description":"` +
		strings.Repeat("x", maxSecretKeyFileSize) +
		`","cborHex":"5820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	path := filepath.Join(t.TempDir(), "payment.vkey")
	require.NoError(t, os.WriteFile(path, []byte(envelope), 0o644))

	key, err := LoadKeyFromFile(path)
	assert.Nil(t, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestLoadKeyFromFileRejectsPermissiveSecret(t *testing.T) {
	wallet, err := NewWallet(testSecretKeyMnemonic)
	require.NoError(t, err)
	data, err := json.Marshal(wallet.PaymentSKey)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "payment.skey")
	require.NoError(t, os.WriteFile(path, data, 0o644))

	key, err := LoadKeyFromFile(path)
	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrInsecureFileMode)
}
