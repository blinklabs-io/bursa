//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

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

package storage

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteStoreUsesOwnerOnlyFilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "wallets.db")

	// Use a permissive umask so this test catches reliance on ambient defaults.
	previousUmask := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(previousUmask) })

	store, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	wallet, err := store.CreateWallet("persisted")
	require.NoError(t, err)
	require.NoError(t, wallet.Save(context.Background()))
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		info, err := os.Stat(dbPath + suffix)
		if os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), suffix)
	}
	require.NoError(t, store.Close())

	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// A pre-existing store with legacy permissions must remain usable while its
	// permissions are narrowed on the next open.
	require.NoError(t, os.Chmod(dbPath, 0o644))
	store, err = NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	info, err = os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	_, err = store.GetWallet(context.Background(), "persisted")
	require.NoError(t, err)
}
