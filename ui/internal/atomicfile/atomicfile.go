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

// Package atomicfile persists owner-only application state.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Replace writes data to an owner-only temporary file, syncs it, replaces path,
// and syncs the parent directory. committed is true once the rename succeeds,
// including when the subsequent directory sync fails.
func Replace(
	path string,
	data []byte,
	syncDir func(string) error,
) (committed bool, err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := replacePath(tmpName, path); err != nil {
		return false, err
	}
	return finishCommit(dir, syncDir)
}

// Remove deletes path and syncs its parent directory. removed is true once the
// directory entry is deleted, including when the subsequent sync fails.
func Remove(
	path string,
	syncDir func(string) error,
) (removed bool, err error) {
	removed, err = removePath(path)
	if err != nil {
		return removed, err
	}
	dir := filepath.Dir(path)
	if !removed {
		if _, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
	}
	_, err = finishCommit(dir, syncDir)
	return removed, err
}

func finishCommit(
	dir string,
	syncDir func(string) error,
) (committed bool, err error) {
	if err := syncDir(dir); err != nil {
		return true, err
	}
	return true, nil
}

// SyncDir flushes a directory entry on platforms that support it.
func SyncDir(dir string) error {
	return syncDirFS(dir)
}
