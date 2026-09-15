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
	"syscall"
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
	return os.OpenFile(
		path,
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
}
