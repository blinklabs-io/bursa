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

//go:build windows

package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// permissiveDir returns a directory whose inheritable ACL grants Everyone full
// control, so any file created in it without an explicit DACL is readable by
// other users.
func permissiveDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sd, err := windows.SecurityDescriptorFromString("D:(A;OICI;GA;;;WD)")
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	))
	return dir
}

func requireOwnerOnly(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err, path)
	defer f.Close()
	assert.NoError(t, bursa.CheckSecretFilePermissions(f), path)
}

func requireNotOwnerOnly(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err, path)
	defer f.Close()
	require.Error(t, bursa.CheckSecretFilePermissions(f), path)
}

func TestSQLiteStoreRestrictsFilesToOwnerUnderPermissiveDirectory(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(permissiveDir(t), "wallets.db")

	store, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	wallet, err := store.CreateWallet("persisted")
	require.NoError(t, err)
	require.NoError(t, wallet.Save(context.Background()))

	// The sidecars must exist while the store is open, or the assertions below
	// would pass without covering them.
	for _, suffix := range []string{"-wal", "-shm"} {
		_, err := os.Stat(dbPath + suffix)
		require.NoError(t, err, suffix)
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Stat(dbPath + suffix); err == nil {
			requireOwnerOnly(t, dbPath+suffix)
		}
	}
}

func TestSQLiteStoreTightensExistingPermissiveDatabase(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(permissiveDir(t), "wallets.db")

	store, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	wallet, err := store.CreateWallet("persisted")
	require.NoError(t, err)
	require.NoError(t, wallet.Save(context.Background()))
	require.NoError(t, store.Close())

	// Re-grant the directory's inherited ACL to the database, as a store
	// created by an older version would have.
	require.NoError(t, os.Remove(dbPath))
	require.NoError(t, os.WriteFile(dbPath, nil, 0o600))
	requireNotOwnerOnly(t, dbPath)

	store, err = NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	requireOwnerOnly(t, dbPath)
	_, err = store.CreateWallet("again")
	require.NoError(t, err)
}

func TestSQLiteStoreReadOnlyDSNTightensExistingDatabaseOnly(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(permissiveDir(t), "wallets.db")
	store, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	require.NoError(t, store.Close())

	ro, err := NewSQLiteStore("file:" + filepath.ToSlash(dbPath) + "?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ro.Close() })
	requireOwnerOnly(t, dbPath)
}
