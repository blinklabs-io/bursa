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

package kesagent

import "syscall"

// withTightUmask runs fn with the process umask set to 0177, so any file it
// creates is born with at most owner read/write and never passes through a
// world-accessible state.
//
// The umask is process-global, so this is only sound for callers that are not
// creating other files concurrently. It is used solely as the fallback path in
// ListenUnix, where the preferred staging-directory approach does not fit
// within the platform's socket pathname limit.
func withTightUmask(fn func() error) error {
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return fn()
}
