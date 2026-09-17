// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build unix

package storage

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openRegularFileForRead opens path for reading without following a final
// symlink and without blocking on a special file.
//
// Inspecting a path and then opening it are two operations, and what the path
// names can change in between: O_NOFOLLOW refuses a symlink substituted after
// the check, and O_NONBLOCK means a FIFO put there returns instead of parking
// the caller until someone writes to it. The same pair guards secret-key reads
// in the root package.
func openRegularFileForRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
}

// openWalletFileForRead walks the wallet path from stable directory
// descriptors so replacing the wallet directory cannot redirect the read.
func openWalletFileForRead(baseDir, name string) (*os.File, error) {
	baseFD, err := unix.Open(baseDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(baseFD)

	dirFD, err := unix.Openat(baseFD, "wallet-"+name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)

	fd, err := unix.Openat(dirFD, filepath.Base("wallet.json"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "wallet.json"), nil
}
