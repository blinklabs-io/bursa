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
	"database/sql/driver"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// permissiveDir returns a directory any user may list and add files to, and
// whose inheritable ACL grants Everyone full control, so any file created in
// it without an explicit DACL is readable by other users. Everyone holds no
// right to delete or rename the directory's own entries, which the store
// requires.
func permissiveDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	makePermissive(t, dir)
	return dir
}

// makePermissive gives dir the DACL permissiveDir describes.
func makePermissive(t *testing.T, dir string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(
		"D:(A;;0x1201bf;;;WD)(A;OICIIO;GA;;;WD)",
	)
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	// The extended-length prefix lets this reach a path past MAX_PATH.
	require.NoError(t, windows.SetNamedSecurityInfo(
		`\\?\`+dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	))
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

func TestSQLiteStoreRestrictsFilesToOwnerUnderPermissiveDirectory(
	t *testing.T,
) {
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

// grantEveryone replaces path's DACL with an unprotected one granting Everyone
// full control, as a file created by an older version inherited.
func grantEveryone(t *testing.T, path string) {
	t.Helper()
	everyone, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;WD)")
	require.NoError(t, err)
	dacl, _, err := everyone.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	))
	requireNotOwnerOnly(t, path)
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
	grantEveryone(t, dbPath)

	store, err = NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	requireOwnerOnly(t, dbPath)
	_, err = store.GetWallet(context.Background(), "persisted")
	require.NoError(t, err)
}

// The files must already be owner-only when SQLite first opens them, not only
// after the store tightens them again.
func TestSQLiteFilesAreOwnerOnlyBeforeSQLiteOpensThem(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(permissiveDir(t), "wallets.db")
	require.NoError(t, ensureSQLiteFilePermissions(dbPath, ""))
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		requireOwnerOnly(t, dbPath+suffix)
	}
}

// A path longer than MAX_PATH has to reach CreateFile in extended-length form.
func TestSQLiteFilePermissionsAcceptLongPaths(t *testing.T) {
	t.Parallel()
	// Only the database's own directory is permissive: every directory above
	// it must deny other users the right to rename entries, or the store
	// rejects the path.
	dir := filepath.Join(
		t.TempDir(),
		strings.Repeat("d", 200),
		strings.Repeat("e", 60),
	)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	makePermissive(t, dir)
	dbPath := filepath.Join(dir, "wallets.db")
	require.Greater(t, len(dbPath), windows.MAX_PATH)
	require.NoError(t, ensureSQLiteFilePermissions(dbPath, ""))
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		requireOwnerOnly(t, dbPath+suffix)
	}
}

// The pool replaces a discarded connection, and closing the last connection
// deletes -wal and -shm, so the replacement recreates them. They must come
// back owner-only.
func TestSQLiteStoreSecuresSidecarsRecreatedForANewConnection(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(permissiveDir(t), "wallets.db")
	store, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	conn, err := store.db.Conn(context.Background())
	require.NoError(t, err)
	require.ErrorIs(
		t,
		conn.Raw(func(any) error { return driver.ErrBadConn }),
		driver.ErrBadConn,
	)
	_ = conn.Close()
	for _, suffix := range []string{"-wal", "-shm"} {
		_, err := os.Stat(dbPath + suffix)
		require.ErrorIs(
			t,
			err,
			fs.ErrNotExist,
			"closing the connection should delete %s",
			suffix,
		)
	}

	wallet, err := store.CreateWallet("after-reconnect")
	require.NoError(t, err)
	require.NoError(t, wallet.Save(context.Background()))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		requireOwnerOnly(t, dbPath+suffix)
	}
}

// An open WAL database needs no new file, so a directory that refuses file
// creation must not stop it opening. Here only -journal is missing.
func TestSQLiteStoreOpensExistingWALDatabaseWhereCreationIsDenied(
	t *testing.T,
) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "wallets.db")
	first, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })
	_, err = os.Stat(dbPath + "-journal")
	require.ErrorIs(t, err, fs.ErrNotExist)

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	sid := user.User.Sid.String()
	// Deny FILE_ADD_FILE on the directory itself; existing files keep their
	// own owner-only DACLs.
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(D;;0x2;;;" + sid + ")(A;OICI;GA;;;" + sid + ")",
	)
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	))
	require.Error(t, os.WriteFile(filepath.Join(dir, "probe"), nil, 0o600))

	second, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })
	_, err = second.ListWallets(context.Background())
	require.NoError(t, err)
}

// setOwnerToLocalSystem makes path belong to another identity, standing in for
// a sidecar a different user pre-created in a shared directory.
func setOwnerToLocalSystem(t *testing.T, path string) {
	t.Helper()
	setOwner(t, path, windows.WinLocalSystemSid)
}

// setOwner makes path belong to the well-known identity sidType. Assigning an
// owner other than the caller needs SeRestorePrivilege, which this enables
// only for the call and only when the process holds it.
func setOwner(t *testing.T, path string, sidType windows.WELL_KNOWN_SID_TYPE) {
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
	require.NoError(
		t,
		windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil),
	)
	defer func() {
		privileges.Privileges[0].Attributes = 0
		_ = windows.AdjustTokenPrivileges(
			token,
			false,
			&privileges,
			0,
			nil,
			nil,
		)
	}()
	owner, err := windows.CreateWellKnownSid(sidType)
	require.NoError(t, err)
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		owner, nil, nil, nil,
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
			// Any secure-file failure satisfies ErrorIs, so pin the rejection
			// to the owner check rather than to an unrelated earlier step.
			require.ErrorContains(t, err, "is owned by")
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
	grantEveryone(t, dbPath)

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

// setDirectoryACE adds sddlACE to dir's DACL alongside the ACEs it inherits.
func setDirectoryACE(t *testing.T, dir, sddlACE string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:" + sddlACE)
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	))
}

// requireDirectoryRejected opens a store at dbPath and requires the directory
// check to refuse it before any file is created, since a principal that can
// delete or rename an entry can replace the database or a sidecar between
// the owner and DACL checks and SQLite opening it.
func requireDirectoryRejected(t *testing.T, dbPath, reason string) {
	t.Helper()
	store, err := NewSQLiteStore(dbPath)
	if store != nil {
		_ = store.Close()
	}
	require.ErrorIs(t, err, bursa.ErrInsecureFileMode)
	require.ErrorContains(t, err, reason)
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		_, err := os.Stat(dbPath + suffix)
		require.ErrorIs(t, err, fs.ErrNotExist, suffix)
	}
}

func TestSQLiteStoreRejectsDirectoryLettingOthersReplaceEntries(t *testing.T) {
	t.Parallel()
	rights := map[string]string{
		"full control": "GA",
		// Read and list, plus FILE_DELETE_CHILD.
		"delete child": "0x1200c9",
		"delete":       "SD",
		"write DAC":    "WD",
		"write owner":  "WO",
	}
	for name, right := range rights {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			setDirectoryACE(t, dir, "(A;;"+right+";;;WD)")
			requireDirectoryRejected(
				t,
				filepath.Join(dir, "wallets.db"),
				"delete or rename",
			)
		})
	}
}

// Replacing any ancestor directory replaces the database path as well.
func TestSQLiteStoreRejectsAncestorLettingOthersReplaceEntries(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	setDirectoryACE(t, parent, "(A;;GA;;;WD)")
	dir := filepath.Join(parent, "store")
	require.NoError(t, os.Mkdir(dir, 0o700))
	requireDirectoryRejected(
		t,
		filepath.Join(dir, "wallets.db"),
		"delete or rename",
	)
}

// The owner of a directory can rewrite its DACL at will. Not parallel: the
// owner change enables a process-wide privilege.
func TestSQLiteStoreRejectsDirectoryOwnedByAnotherIdentity(t *testing.T) {
	dir := t.TempDir()
	setOwner(t, dir, windows.WinBuiltinUsersSid)
	requireDirectoryRejected(
		t,
		filepath.Join(dir, "wallets.db"),
		"directory",
	)
}

func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).
		CombinedOutput()
	require.NoError(t, err, string(out))
}

// addReparsePointACE adds sddlACE to the DACL of the junction at link itself,
// which SetNamedSecurityInfo would apply to the target instead.
func addReparsePointACE(t *testing.T, link, sddlACE string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:" + sddlACE)
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	name, err := windows.UTF16PtrFromString(link)
	require.NoError(t, err)
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|
			windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	require.NoError(t, err)
	defer func() { _ = windows.CloseHandle(handle) }()
	require.NoError(t, windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	))
}

// Windows lets FSCTL_SET_REPARSE_POINT through a handle with either write
// right, so whoever holds one on a junction can retarget it, and with it
// the database path, after the directories are checked.
func TestSQLiteStoreRejectsReparsePointOthersCanRetarget(t *testing.T) {
	t.Parallel()
	rights := map[string]string{
		// Read and list, plus FILE_WRITE_DATA.
		"write data": "0x12008b",
		// Read and list, plus FILE_WRITE_ATTRIBUTES.
		"write attributes": "0x120189",
		"generic write":    "GW",
	}
	for name, right := range rights {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			target := filepath.Join(base, "target")
			require.NoError(t, os.Mkdir(target, 0o700))
			link := filepath.Join(base, "link")
			makeJunction(t, link, target)
			addReparsePointACE(t, link, "(A;;"+right+";;;WD)")
			requireDirectoryRejected(
				t,
				filepath.Join(link, "wallets.db"),
				"reparse point",
			)
		})
	}
}

func TestSQLiteStoreOpensThroughJunctionOthersCannotRetarget(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(base, "link")
	makeJunction(t, link, target)

	store, err := NewSQLiteStore(filepath.Join(link, "wallets.db"))
	require.NoError(t, err)
	require.NoError(t, store.Close())
	requireOwnerOnly(t, filepath.Join(target, "wallets.db"))
}

// An empty directory can be turned into a junction by anyone allowed to add
// a file to it, so the database's directory can change after it is checked
// and before the database is first created in it. Not parallel: the hook is
// package state.
func TestSQLiteStoreRejectsDirectoryRetargetedAfterCheck(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "store")
	require.NoError(t, os.Mkdir(dir, 0o700))
	elsewhere := filepath.Join(base, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	var once sync.Once
	sqliteAfterDirectoryCheck = func() {
		once.Do(func() {
			require.NoError(t, os.Remove(dir))
			makeJunction(t, dir, elsewhere)
		})
	}
	t.Cleanup(func() { sqliteAfterDirectoryCheck = nil })

	store, err := NewSQLiteStore(filepath.Join(dir, "wallets.db"))
	if store != nil {
		_ = store.Close()
	}
	require.ErrorIs(t, err, bursa.ErrInsecureFileMode)
	require.ErrorContains(t, err, "outside the checked directory")
	if info, err := os.Stat(filepath.Join(elsewhere, "wallets.db")); err == nil {
		assert.Zero(t, info.Size(), "SQLite wrote to the retargeted path")
	}
}
