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

package signer

import (
	"os"
	"syscall"
)

// openDirSecret opens a secret file without blocking: a FIFO in its place
// would otherwise block the open until a writer appears. Symlinks are followed
// on purpose, since a Kubernetes Secret volume links each file through
// ..data; the caller rejects anything that is not a regular file.
func openDirSecret(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
