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

//go:build !unix

package storage

import "os"

// openRegularFileForRead opens path for reading.
//
// Platforms without O_NOFOLLOW/O_NONBLOCK get a plain open; the caller's
// post-open check that the handle is a regular file is what carries the
// guarantee here, as it does for secret-key reads in the root package.
func openRegularFileForRead(path string) (*os.File, error) {
	return os.Open(path)
}
