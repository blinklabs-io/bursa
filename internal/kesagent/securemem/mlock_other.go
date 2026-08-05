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

//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package securemem

import "errors"

// errNoMlock signals that memory locking is unavailable on this platform.
var errNoMlock = errors.New("securemem: mlock not supported on this platform")

func lockMemory(_ []byte) error   { return errNoMlock }
func unlockMemory(_ []byte) error { return nil }
