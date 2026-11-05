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
	"errors"
	"io/fs"
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
		_, err := os.Stat(dbPath + suffix)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		require.NoError(t, err, suffix)
		requireOwnerOnly(t, dbPath+suffix)
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

// setOwnerToLocalSystem makes path belong to another identity, standing in for
// a sidecar a different user pre-created in a shared directory. Assigning an
// owner other than the caller needs SeRestorePrivilege, which this enables
// only for the call and only when the process holds it.
func setOwnerToLocalSystem(t *testing.T, path string) {
	t.Helper()
	var token windows.Token
	require.NoError(t, windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	))
	defer token.Close()
	var luid windows.LUID
	require.NoError(t, windows.LookupPrivilegeValue(
		nil, windows.StringToUTF16Ptr("SeRestorePrivilege"), &luid,
	))
	privileges := windows.Tokenprivileges{PrivilegeCount: 1}
	privileges.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}
	require.NoError(t, windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil))
	defer func() {
		privileges.Privileges[0].Attributes = 0
		_ = windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)
	}()
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		system, nil, nil, nil,
	)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		t.Skip("SeRestorePrivilege is not held; cannot assign another owner")
	}
	require.NoError(t, err)
}

func securityDescriptorString(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	require.NoError(t, err, path)
	return sd.String()
}

// A database or sidecar another identity created can still be open in that
// identity's process, and a handle survives any later DACL change, so taking
// ownership and tightening the DACL would hand that process what SQLite
// writes. The file must be rejected before its owner or DACL is changed. Not
// parallel: the owner change enables a process-wide privilege.
func TestSQLiteStoreRejectsFilesOwnedByAnotherIdentity(t *testing.T) {
	for _, suffix := range []string{"", "-wal"} {
		t.Run("suffix="+suffix, func(t *testing.T) {
			dbPath := filepath.Join(permissiveDir(t), "wallets.db")
			foreign := dbPath + suffix
			require.NoError(t, os.WriteFile(foreign, nil, 0o600))
			setOwnerToLocalSystem(t, foreign)
			before := securityDescriptorString(t, foreign)

			store, err := NewSQLiteStore(dbPath)
			if store != nil {
				_ = store.Close()
			}
			require.ErrorIs(t, err, bursa.ErrInsecureFileMode)
			assert.Equal(t, before, securityDescriptorString(t, foreign))
		})
	}
}

// A read-only connection to a WAL database creates -wal and -shm itself when
// the directory allows it, so a read-only open must still secure them, and
// must not fail for a database whose sidecars are absent.
func TestSQLiteStoreReadOnlyDSNSecuresDatabaseAndSidecars(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(permissiveDir(t), "wallets.db")
	store, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		_, err := os.Stat(dbPath + suffix)
		require.ErrorIs(t, err, fs.ErrNotExist, suffix)
	}
	everyone, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;WD)")
	require.NoError(t, err)
	dacl, _, err := everyone.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(
		dbPath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	))
	requireNotOwnerOnly(t, dbPath)

	ro, err := NewSQLiteStore("file:" + filepath.ToSlash(dbPath) + "?mode=ro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ro.Close() })
	_, err = ro.ListWallets(context.Background())
	require.NoError(t, err)

	requireOwnerOnly(t, dbPath)
	for _, suffix := range []string{"-wal", "-shm"} {
		requireOwnerOnly(t, dbPath+suffix)
	}
}
