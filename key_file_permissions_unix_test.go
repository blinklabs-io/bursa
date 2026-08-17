//go:build unix

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
	"syscall"
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

func TestReadSecretKeyFileRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.skey")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	_, err := ReadSecretKeyFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not a regular file")
}

func TestCreateSecretKeyFileUnixIsExclusiveAndRestrictive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.skey")
	file, err := CreateSecretKeyFile(path)
	require.NoError(t, err)
	require.NoError(t, file.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	_, err = CreateSecretKeyFile(path)
	assert.Error(t, err)

	target := filepath.Join(dir, "target.skey")
	require.NoError(t, os.WriteFile(target, []byte("unchanged"), 0o600))
	link := filepath.Join(dir, "link.skey")
	require.NoError(t, os.Symlink(target, link))
	_, err = CreateSecretKeyFile(link)
	assert.Error(t, err)
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "unchanged", string(data))
}

func TestWriteSecretKeyFileUnixAtomicallyReplacesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.skey")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))
	require.NoError(t, WriteSecretKeyFile(path, []byte("new")))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new", string(data))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestLoadWalletDirSkipsPermissiveSecretKey(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "payment.skey")
	publicPath := filepath.Join(tmpDir, "payment.vkey")
	secret := `{"type":"PaymentSigningKeyShelley_ed25519","description":"Payment Signing Key","cborHex":"5820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	public := `{"type":"PaymentVerificationKeyShelley_ed25519","description":"Payment Verification Key","cborHex":"5820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	require.NoError(t, os.WriteFile(secretPath, []byte(secret), 0o644))
	require.NoError(t, os.WriteFile(publicPath, []byte(public), 0o644))

	loaded, err := LoadWalletDir(tmpDir, true)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "payment.vkey", loaded[0].File)
}
