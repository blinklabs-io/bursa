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

	"github.com/blinklabs-io/bursa"
	"golang.org/x/sys/windows"
)

// sqliteSidecarSuffixes are the files SQLite creates next to the database. On
// Windows a new file inherits the parent directory's ACL, so each one has to
// carry an owner-only DACL before SQLite writes secrets into it.
var sqliteSidecarSuffixes = []string{"-wal", "-shm", "-journal"}

// openSQLiteSecurityHandle opens path for DACL changes only. Requesting no data
// access keeps the open compatible with the share mode SQLite holds the file
// under, so a live database can be re-secured.
func openSQLiteSecurityHandle(path string, create bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.OPEN_ALWAYS
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func secureSQLiteFile(path string, create bool) error {
	f, err := openSQLiteSecurityHandle(path, create)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := bursa.RestrictSecretKeyFilePermissions(f); err != nil {
		return err
	}
	return bursa.CheckSecretFilePermissions(f)
}

// ensureSQLiteFilePermissions gives the database and its sidecars an
// owner-only, non-inherited DACL before SQLite opens the database. The
// sidecars are created empty here because SQLite would otherwise create them
// itself with the directory's inherited ACL and write secrets through them; an
// empty -wal or -shm is a valid starting state. An existing database with a
// permissive DACL is tightened, as the Unix path narrows the mode.
func ensureSQLiteFilePermissions(path, mode string) error {
	// A DSN that says how it wants the file opened is entitled to that: "ro"
	// and "rw" open only a database that already exists, and "ro" must not
	// create anything beside it.
	create := true
	switch mode {
	case "ro", "rw":
		if !sqliteFileExists(path) {
			return nil
		}
		create = false
	}
	if err := secureSQLiteFile(path, create); err != nil {
		return err
	}
	for _, suffix := range sqliteSidecarSuffixes {
		if err := secureSQLiteFile(path+suffix, mode != "ro"); err != nil {
			return fmt.Errorf("%s: %w", suffix, err)
		}
	}
	return nil
}

// secureSQLiteSidecars re-applies the DACL to every file that exists, covering
// files SQLite recreated after the pre-creation in ensureSQLiteFilePermissions.
func secureSQLiteSidecars(path string) error {
	for _, suffix := range append([]string{""}, sqliteSidecarSuffixes...) {
		if err := secureSQLiteFile(path+suffix, false); err != nil &&
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
