//go:build !windows

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecretKeyMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func writeTestSecretKey(t *testing.T) string {
	t.Helper()
	wallet, err := NewWallet(testSecretKeyMnemonic)
	require.NoError(t, err)
	data, err := json.Marshal(wallet.PaymentSKey)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "payment.skey")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestLoadSecretKeyFromFileRejectsPermissiveMode(t *testing.T) {
	path := writeTestSecretKey(t)
	require.NoError(t, os.Chmod(path, 0o644))

	key, err := LoadSecretKeyFromFile(path)
	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrInsecureFileMode)
	assert.Contains(t, err.Error(), "mode 0644")
}

func TestLoadSecretKeyFromFilePreservesFileName(t *testing.T) {
	path := writeTestSecretKey(t)

	key, err := LoadSecretKeyFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, filepath.Base(path), key.File)
}
