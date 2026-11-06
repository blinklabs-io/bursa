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

//go:build !windows

package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

func ensureSQLiteFilePermissions(path, mode string) error {
	// A DSN that says how it wants the file opened is entitled to that: "ro"
	// must not be opened for writing, and "rw" opens only what already exists,
	// so creating it here would answer a missing-database error with an empty
	// database. In both cases a file that is not there is SQLite's to report.
	flags := os.O_RDWR | os.O_CREATE
	switch mode {
	case "ro":
		if !sqliteFileExists(path) {
			return nil
		}
		flags = os.O_RDONLY
	case "rw":
		if !sqliteFileExists(path) {
			return nil
		}
		flags = os.O_RDWR
	}
	f, err := os.OpenFile(path, flags, sqliteFileMode)
	if err != nil {
		return err
	}
	if err := f.Chmod(sqliteFileMode); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func secureSQLiteSidecars(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Chmod(path+suffix, sqliteFileMode); err != nil &&
			!errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", suffix, err)
		}
	}
	return nil
}
