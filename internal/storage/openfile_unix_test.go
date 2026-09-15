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
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The wallet load inspects a path and then opens it, and what the path names
// can change in between. These cover the open itself, since the race that
// substitutes the file cannot be staged from outside the function.

// A FIFO put in place of a regular file parks a plain open until someone writes
// to it — the wallet load would never return.
func TestOpenRegularFileForReadDoesNotBlockOnAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swapped")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	type opened struct {
		regular bool
		err     error
	}
	done := make(chan opened, 1)
	go func() {
		f, err := openRegularFileForRead(path)
		if err != nil {
			done <- opened{err: err}
			return
		}
		defer f.Close()
		info, statErr := f.Stat()
		done <- opened{regular: statErr == nil && info.Mode().IsRegular()}
	}()

	// O_NONBLOCK makes the open itself return rather than wait for a writer;
	// what rejects the FIFO is the caller's check that the handle it got is a
	// regular file. Both halves matter: returning promptly is what keeps the
	// wallet load from hanging, and the check is what keeps it from reading.
	select {
	case got := <-done:
		if got.regular {
			t.Fatal("a FIFO must not present as a regular file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("open blocked on the FIFO")
	}
}

// A symlink put in place of the checked file must not redirect the read.
func TestOpenRegularFileForReadRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	f, err := openRegularFileForRead(link)
	if err == nil {
		f.Close()
		t.Fatal("a final symlink should not be followed")
	}
}
