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
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestDirSecretSource_FIFO checks that a FIFO named like a secret is neither
// listed nor able to block Get: opening a FIFO for reading blocks until a
// writer appears unless the open is non-blocking.
func TestDirSecretSource_FIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.json"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	src, err := NewDirSecretSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	names, err := src.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("List = %v, want no secrets", names)
	}
	done := make(chan error, 1)
	go func() {
		_, err := src.Get(context.Background(), "pipe.json")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Get to refuse a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Get blocked on a FIFO")
	}
}
