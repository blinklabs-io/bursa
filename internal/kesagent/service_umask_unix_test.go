//go:build unix

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

package kesagent

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestListenUnixMode0600UnderPermissiveUmask verifies ListenUnix publishes the
// socket at its final restrictive mode even under a permissive umask (0), where
// a plain net.Listen would create it world-writable and only tighten it one
// syscall later — a window in which a connection could be made that survives the
// chmod. The socket at its advertised path must be connectable and never
// group/other accessible.
func TestListenUnixMode0600UnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	sock := shortSocketPath(t, "umask.sock")
	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %04o under umask 0, want 0600 (no group/other access)", perm)
	}
	// The published path must be a working listener (kernel accepts into the
	// backlog without an Accept call).
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial published socket: %v", err)
	}
	_ = conn.Close()
}
