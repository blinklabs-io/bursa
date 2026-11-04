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

//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockState takes an exclusive lock on the state directory for the life of
// the process. The lock file stays open, so the lock is released only when
// the process exits.
func lockState(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // a file descriptor fits an int
		f.Close() //nolint:errcheck,gosec // the lock error is returned
		return fmt.Errorf("state directory %s is in use by another armory-sim: %w", dir, err)
	}

	return nil
}
