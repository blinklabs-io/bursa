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

//go:build unix && !aix

package kesagent

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockGuardFile opens (creating if needed) the lock file at path and takes an
// exclusive, non-blocking flock on it. The lock is released when the returned
// file is closed, or by the kernel when the process exits. ErrGuardLocked is
// returned when another open file description holds it.
func lockGuardFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("kesagent: open guard lock %q: %w", path, err)
	}
	fd := int(f.Fd()) // #nosec G115 -- a file descriptor fits in an int
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf(
				"%w: %q is held by another agent process",
				ErrGuardLocked,
				path,
			)
		}
		return nil, fmt.Errorf("kesagent: lock guard %q: %w", path, err)
	}
	return f, nil
}
