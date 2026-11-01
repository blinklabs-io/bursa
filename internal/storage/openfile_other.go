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

//go:build !unix && !windows

package storage

import (
	"os"
	"path/filepath"

	"github.com/blinklabs-io/bursa"
)

const inspectWalletPathsByName = true

// openRegularFileForRead opens path for reading.
//
// Platforms without O_NOFOLLOW/O_NONBLOCK get a plain open; the caller's
// post-open check that the handle is a regular file is what carries the
// guarantee here, as it does for secret-key reads in the root package.
func openRegularFileForRead(path string) (*os.File, error) {
	return os.Open(path)
}

func openWalletFileForRead(baseDir, name string) (*os.File, error) {
	return os.Open(filepath.Join(baseDir, "wallet-"+name, "wallet.json"))
}

func ensureWalletDirectory(path string) error {
	return os.MkdirAll(path, 0o700)
}

func readWalletDirectory(baseDir string) ([]os.DirEntry, error) {
	return os.ReadDir(baseDir)
}

func writeWalletFile(baseDir, name string, data []byte) error {
	if err := ensureWalletDirectory(baseDir); err != nil {
		return err
	}
	walletDir := filepath.Join(baseDir, "wallet-"+name)
	if err := ensureWalletDirectory(walletDir); err != nil {
		return err
	}
	return bursa.WriteSecretKeyFile(filepath.Join(walletDir, "wallet.json"), data)
}

func deleteWallet(baseDir, name string) error {
	walletDir := filepath.Join(baseDir, "wallet-"+name)
	if _, err := os.Lstat(walletDir); err != nil {
		return err
	}
	return os.RemoveAll(walletDir)
}

// checkWalletFileMode is a no-op where file modes do not describe access.
func checkWalletFileMode(os.FileInfo) error { return nil }
