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
		return fmt.Errorf("%q has no readable owner: %w", f.Name(), bursa.ErrInsecureFileMode)
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

// sqliteCreate says whether secureSQLiteFile may create a missing file.
type sqliteCreate int

const (
	// sqliteOpenExisting secures only a file that exists.
	sqliteOpenExisting sqliteCreate = iota
	// sqliteCreateRequired creates a missing file and fails if it cannot.
	sqliteCreateRequired
	// sqliteCreateIfPermitted creates a missing file, and leaves it missing
	// when the directory refuses the creation.
	sqliteCreateIfPermitted
)

// secureSQLiteFile leaves path with an owner-only DACL. A missing file that
// may be created is created with that DACL already applied, so no other
// identity can open it before it is restricted. Every file, new or not, is
// then reopened without following reparse points and its owner is checked
// before its DACL is touched, so a foreign-owned file is rejected unchanged.
func secureSQLiteFile(path string, create sqliteCreate) error {
	createDenied := false
	if create != sqliteOpenExisting {
		f, err := bursa.CreateSecretKeyFile(path)
		switch {
		case err == nil:
			if err := f.Close(); err != nil {
				return err
			}
		case errors.Is(err, fs.ErrExist):
		case create == sqliteCreateIfPermitted && errors.Is(err, fs.ErrPermission):
			createDenied = true
		default:
			return err
		}
	}
	f, err := openSQLiteSecurityHandle(path)
	if createDenied && errors.Is(err, fs.ErrNotExist) {
		return nil
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

// ensureSQLiteFilePermissions gives the database and its sidecars an
// owner-only, non-inherited DACL before SQLite opens the database. The
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
	if err := secureSQLiteFile(path, createDB); err != nil {
		return err
	}
	// A read-only connection to a WAL database still creates -wal and -shm
	// when the directory allows it, so they are created here for "ro" too.
	// Where the directory refuses, SQLite cannot create them either.
	createSidecar := sqliteCreateRequired
	if mode == "ro" {
		createSidecar = sqliteCreateIfPermitted
	}
	for _, suffix := range sqliteSidecarSuffixes {
		if err := secureSQLiteFile(path+suffix, createSidecar); err != nil {
			return fmt.Errorf("%s: %w", suffix, err)
		}
	}
	return nil
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
