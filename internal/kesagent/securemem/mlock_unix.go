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

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package securemem

// golang.org/x/sys/unix rather than syscall: the stdlib only defines
// Mlock/Munlock on linux and darwin, so building this file for the BSDs in the
// constraint above failed to compile at all (it broke every release build on
// freebsd). x/sys/unix defines them for all six, and is pure Go, so the root
// module stays CGO-free.
import "golang.org/x/sys/unix"

func lockMemory(b []byte) error   { return unix.Mlock(b) }
func unlockMemory(b []byte) error { return unix.Munlock(b) }
