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

// TestListenUnixNearPathnameLimit covers a socket path that fits within the
// platform's sockaddr_un limit but leaves no room for the staging directory
// component ListenUnix normally binds inside. Such a path bound fine before
// staging was introduced, so it must keep working — via the umask-bracketed
// fallback — rather than failing with "invalid argument".
func TestListenUnixNearPathnameLimit(t *testing.T) {
	// sun_path is 108 bytes on Linux but 104 on macOS and the BSDs, so take it
	// from the platform's own sockaddr rather than assuming Linux's size: a
	// hardcoded 107 would build paths this platform cannot bind at all, testing
	// a bind failure instead of the fallback.
	maxSunPath := len(syscall.RawSockaddrUnix{}.Path) - 1
	// The staged path adds "/.kes-sock-<10 random>/s" to the parent directory.
	stagingOverhead := len("/.kes-sock-0123456789/s")

	base := "s.sock"
	dir := t.TempDir()
	// Pad the directory so the final path still fits but the staged one cannot.
	target := maxSunPath - len(base) - 1
	if len(dir) > target {
		t.Skipf("temp dir %q (%d bytes) is already too long for this case", dir, len(dir))
	}
	for len(dir)+stagingOverhead <= maxSunPath {
		next := dir + "/p"
		if len(next)+1+len(base) > maxSunPath {
			break
		}
		if err := os.Mkdir(next, 0o700); err != nil {
			t.Fatalf("mkdir %q: %v", next, err)
		}
		dir = next
	}
	sock := dir + "/" + base
	if len(sock) > maxSunPath {
		t.Fatalf("constructed path %d bytes, want <= %d", len(sock), maxSunPath)
	}
	if len(dir)+stagingOverhead <= maxSunPath {
		t.Skipf("could not build a directory long enough to overflow staging (dir %d bytes)", len(dir))
	}

	// Permissive umask: the fallback must still publish a 0600 socket.
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	ln, err := ListenUnix(sock, 0o600)
	if err != nil {
		t.Fatalf("ListenUnix(%d-byte path): %v", len(sock), err)
	}
	defer func() { _ = ln.Close() }()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %04o, want 0600 even on the fallback path", perm)
	}
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial published socket: %v", err)
	}
	_ = conn.Close()
}
