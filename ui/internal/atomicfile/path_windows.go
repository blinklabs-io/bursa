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

package atomicfile

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const durableMoveFlags = windows.MOVEFILE_REPLACE_EXISTING |
	windows.MOVEFILE_WRITE_THROUGH

func replacePath(oldPath, newPath string) error {
	oldPtr, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldPtr, newPtr, durableMoveFlags)
}

func removePath(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	tombstone, err := os.CreateTemp(filepath.Dir(path), ".removed-*")
	if err != nil {
		return false, err
	}
	tombstonePath := tombstone.Name()
	if err := tombstone.Close(); err != nil {
		_ = os.Remove(tombstonePath)
		return false, err
	}
	defer func() { _ = os.Remove(tombstonePath) }()

	if err := replacePath(path, tombstonePath); err != nil {
		return false, err
	}
	if err := os.Remove(tombstonePath); err != nil {
		return true, err
	}
	return true, nil
}
