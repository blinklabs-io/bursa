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
	"fmt"
	"os"
	"path/filepath"

	"github.com/blinklabs-io/bursa"
	"golang.org/x/sys/unix"
)

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

// checkWalletFileMode rejects a wallet file other users can access. Saves
// create it owner-only, so any group or other bit means it was changed since.
func checkWalletFileMode(info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf(
			"wallet file has mode %04o; group/other access is not permitted: %w",
			mode, bursa.ErrInsecureFileMode,
		)
	}
	return nil
}
