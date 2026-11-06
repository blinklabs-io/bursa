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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/blinklabs-io/bursa"
	"golang.org/x/sys/windows"
)

// sqliteSidecarSuffixes are the files SQLite creates next to the database. On
// Windows a new file inherits the parent directory's ACL, so each one has to
// carry an owner-only DACL before SQLite writes secrets into it.
var sqliteSidecarSuffixes = []string{"-wal", "-shm", "-journal"}

// openSQLiteSecurityHandle opens an existing path for DACL changes only.
// Requesting no data access keeps the open compatible with the share mode
// SQLite holds the file under, so a live database can be re-secured. The path
// itself is opened, never a reparse point's target, and anything other than a
// regular file is rejected: a link planted at a sidecar name would otherwise
// redirect both the DACL change and SQLite's writes to another file.
func openSQLiteSecurityHandle(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	var tagInfo struct {
		FileAttributes uint32
		ReparseTag     uint32
	}
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&tagInfo)),
		uint32(unsafe.Sizeof(tagInfo)),
	); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to read attributes of %q: %w", path, err)
	}
	if tagInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|
		windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf(
			"%q is not a regular file: %w", path, bursa.ErrInsecureFileMode,
		)
	}
	return os.NewFile(uintptr(handle), path), nil
}

// checkSQLiteFileOwner accepts a file owned by the current user, or by
// Administrators as a file created from an elevated process is. Any other
// owner may still hold a handle opened under the file's earlier DACL, and a
// handle outlives a DACL change, so adopting the file would give that holder
// whatever SQLite writes into it.
func checkSQLiteFileOwner(f *os.File) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(f.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("failed to read owner of %q: %w", f.Name(), err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf(
			"%q has no readable owner: %w",
			f.Name(),
			bursa.ErrInsecureFileMode,
		)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("failed to get current user SID: %w", err)
	}
	if owner.Equals(user.User.Sid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return fmt.Errorf(
		"%q is owned by %s, not the current user: %w",
		f.Name(), owner, bursa.ErrInsecureFileMode,
	)
}

// sqliteWin32Path returns path in extended-length form, which CreateFile
// needs for a path longer than MAX_PATH. os.OpenFile adds the prefix itself;
// the direct CreateFile calls here and in bursa.CreateSecretKeyFile do not.
// The path is made absolute first, which also turns forward slashes into
// separators, since the prefix disables that normalization.
func sqliteWin32Path(path string) (string, error) {
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return path, nil
	}
	full, err := windows.FullPath(path)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(full, `\\`) {
		return `\\?\UNC\` + full[2:], nil
	}
	return `\\?\` + full, nil
}

// sqliteCreate says whether secureSQLiteFile may create a missing file.
type sqliteCreate int

const (
	// sqliteOpenExisting secures only a file that exists.
	sqliteOpenExisting sqliteCreate = iota
	// sqliteCreateRequired creates a missing file and fails if it cannot.
	sqliteCreateRequired
	// sqliteCreateIfPermitted creates a missing file, and leaves it missing
	// when the directory refuses the creation, since SQLite cannot create it
	// there either.
	sqliteCreateIfPermitted
)

// secureSQLiteFile leaves path with an owner-only DACL. A missing file that
// may be created is created with that DACL already applied, so no other
// identity can open it before it is restricted. Every file, new or not, is
// then reopened without following reparse points and its owner is checked
// before its DACL is touched, so a foreign-owned file is rejected unchanged.
func secureSQLiteFile(path string, create sqliteCreate) error {
	path, err := sqliteWin32Path(path)
	if err != nil {
		return err
	}
	var createErr error
	if create != sqliteOpenExisting {
		f, err := bursa.CreateSecretKeyFile(path)
		switch {
		case err == nil:
			if err := f.Close(); err != nil {
				return err
			}
		case errors.Is(err, fs.ErrExist):
		case errors.Is(err, fs.ErrPermission):
			// A directory that refuses new files may still hold this one.
			createErr = err
		default:
			return err
		}
	}
	f, err := openSQLiteSecurityHandle(path)
	if createErr != nil && errors.Is(err, fs.ErrNotExist) {
		if create == sqliteCreateIfPermitted {
			return nil
		}
		return createErr
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := checkSQLiteFileOwner(f); err != nil {
		return err
	}
	if err := bursa.RestrictSecretKeyFilePermissions(f); err != nil {
		return err
	}
	return bursa.CheckSecretFilePermissions(f)
}

// ensureSQLiteFilePermissions refuses a directory another identity can
// replace entries in, then gives the database and its sidecars an owner-only,
// non-inherited DACL before SQLite opens the database. The
// sidecars are created empty here because SQLite would otherwise create them
// itself with the directory's inherited ACL and write secrets through them;
// SQLite's Windows VFS treats a zero-length file as absent and opens an
// existing one without replacing its DACL. An existing database with a
// permissive DACL is tightened, as the Unix path narrows the mode, but only
// when its owner passes checkSQLiteFileOwner, as chmod on Unix fails for a
// file another user owns.
func ensureSQLiteFilePermissions(path, mode string) error {
	// "ro" and "rw" open only a database that already exists, so the database
	// itself is never created for them.
	createDB := sqliteCreateRequired
	switch mode {
	case "ro", "rw":
		if !sqliteFileExists(path) {
			return nil
		}
		createDB = sqliteOpenExisting
	}
	if err := checkSQLiteDirectories(path); err != nil {
		return err
	}
	if err := secureSQLiteFile(path, createDB); err != nil {
		return err
	}
	// Sidecars are created in every mode, "ro" included: a read-only
	// connection to a WAL database still creates -wal and -shm when the
	// directory allows it. Where the directory refuses, SQLite cannot create
	// them either, and an open WAL database needs no new file.
	for _, suffix := range sqliteSidecarSuffixes {
		if err := secureSQLiteFile(path+suffix, sqliteCreateIfPermitted); err != nil {
			return fmt.Errorf("%s: %w", suffix, err)
		}
	}
	return nil
}

// fileDeleteChild is FILE_DELETE_CHILD, which x/sys/windows does not export.
const fileDeleteChild = 0x40

// sqliteDirectoryUnsafeRights are the directory rights that let a holder
// replace an entry: delete or rename one (FILE_DELETE_CHILD), delete or rename
// the directory itself (DELETE), or grant itself either (WRITE_DAC,
// WRITE_OWNER, GENERIC_ALL).
const sqliteDirectoryUnsafeRights = fileDeleteChild | windows.DELETE |
	windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// trustedInstallerSID is NT SERVICE\TrustedInstaller, which owns the system
// directories a store path can pass through, such as the volume root.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-" +
	"1853292631-2271478464"

// checkSQLiteDirectories refuses a database whose directory, or any ancestor,
// lets another identity delete or rename entries. Such an identity could
// replace the database or a sidecar after the owner and DACL checks on it and
// before SQLite opens it, and SQLite would then write into the replacement.
// Both the path as given and the path its links resolve to are checked: the
// first covers a link that could be retargeted, the second the directories
// SQLite actually writes in.
func checkSQLiteDirectories(dbPath string) error {
	path, err := sqliteWin32Path(dbPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := checkSQLiteDirectoryChain(dir); err != nil {
		return err
	}
	resolved, err := sqliteResolvedPath(dir)
	if err != nil {
		return err
	}
	if strings.EqualFold(resolved, dir) {
		return nil
	}
	return checkSQLiteDirectoryChain(resolved)
}

func checkSQLiteDirectoryChain(dir string) error {
	for {
		if err := checkSQLiteDirectory(dir); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// sqliteResolvedPath returns dir with every link and short name resolved.
func sqliteResolvedPath(dir string) (string, error) {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(
		name,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("failed to open directory %q: %w", dir, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(
		handle, &buf[0], windows.MAX_LONG_PATH, 0,
	)
	if err != nil {
		return "", fmt.Errorf("failed to resolve directory %q: %w", dir, err)
	}
	if int(n) >= len(buf) {
		return "", fmt.Errorf("resolved path of directory %q is too long", dir)
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// checkSQLiteDirectory reads dir's own owner and DACL, not a link target's,
// and rejects an untrusted owner or any ACE that applies to dir and grants an
// untrusted identity one of sqliteDirectoryUnsafeRights. Deny ACEs are
// ignored rather than netted off, which can only reject more.
func checkSQLiteDirectory(dir string) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("failed to open directory %q: %w", dir, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to read security of directory %q: %w",
			dir,
			err,
		)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("failed to get current user SID: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf(
			"sqlite database directory %q has no readable owner: %w",
			dir, bursa.ErrInsecureFileMode,
		)
	}
	if !sqliteTrustedDirectoryIdentity(owner, user.User.Sid) {
		return fmt.Errorf(
			"sqlite database directory %q is owned by %s: %w",
			dir, owner, bursa.ErrInsecureFileMode,
		)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		// A missing DACL grants everyone full control.
		return fmt.Errorf(
			"sqlite database directory %q has no DACL: %w",
			dir, bursa.ErrInsecureFileMode,
		)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf(
				"failed to read ACE %d of directory %q: %w", i, dir, err,
			)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf(
				"sqlite database directory %q has an ACE of unsupported type %d: %w",
				dir,
				ace.Header.AceType,
				bursa.ErrInsecureFileMode,
			)
		}
		if ace.Mask&sqliteDirectoryUnsafeRights == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sqliteTrustedDirectoryIdentity(sid, user.User.Sid) ||
			sqliteOwnerPlaceholder(sid) {
			continue
		}
		return fmt.Errorf(
			"sqlite database directory %q lets %s delete or rename its entries: %w",
			dir,
			sid,
			bursa.ErrInsecureFileMode,
		)
	}
	return nil
}

// sqliteTrustedDirectoryIdentity reports whether sid is the current user or
// an identity that already controls every file on the machine.
func sqliteTrustedDirectoryIdentity(sid, currentUser *windows.SID) bool {
	return sid.Equals(currentUser) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.String() == trustedInstallerSID
}

// sqliteOwnerPlaceholder reports whether sid stands for the object's owner
// rather than for an identity: CREATOR OWNER and CREATOR GROUP grant nothing
// on the object that carries them, and OWNER RIGHTS applies to its owner,
// which the owner check has already accepted.
func sqliteOwnerPlaceholder(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinCreatorOwnerSid) ||
		sid.IsWellKnown(windows.WinCreatorGroupSid) ||
		sid.String() == "S-1-3-4"
}

// secureSQLiteSidecars re-applies the DACL to every file that exists, covering
// files SQLite recreated after the pre-creation in ensureSQLiteFilePermissions.
func secureSQLiteSidecars(path string) error {
	for _, suffix := range append([]string{""}, sqliteSidecarSuffixes...) {
		if err := secureSQLiteFile(path+suffix, sqliteOpenExisting); err != nil &&
			!errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", suffix, err)
		}
	}
	// In WAL mode the rollback journal is unused, so the empty one created
	// ahead of SQLite is clutter. A non-empty or in-use file stays.
	if info, err := os.Stat(path + "-journal"); err == nil && info.Size() == 0 {
		_ = os.Remove(path + "-journal")
	}
	return nil
}
