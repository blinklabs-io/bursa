//go:build unix

// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestListenPrivateUnixNeverPublishesWorldWritableMode(t *testing.T) {
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o600, 0o660} {
		for i := range 128 {
			path := filepath.Join(
				dir,
				fmt.Sprintf("nitro-%04o-%d.sock", mode, i),
			)
			started := make(chan struct{})
			stop := make(chan struct{})
			done := make(chan struct{})
			permissive := make(chan os.FileMode, 1)
			go func() {
				defer close(done)
				close(started)
				for {
					select {
					case <-stop:
						return
					default:
					}
					if info, err := os.Lstat(path); err == nil &&
						info.Mode().Perm()&0o007 != 0 {
						select {
						case permissive <- info.Mode().Perm():
						default:
						}
						return
					}
					runtime.Gosched()
				}
			}()
			<-started

			listener, err := listenPrivateUnix(path, mode)
			if err != nil {
				close(stop)
				t.Fatalf("listenPrivateUnix: %v", err)
			}
			close(stop)
			<-done
			_ = listener.Close()
			select {
			case mode := <-permissive:
				t.Fatalf("Nitro proxy socket was published with mode %04o", mode)
			default:
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("stat Nitro proxy socket: %v", err)
			}
			if got := info.Mode().Perm(); got != mode {
				t.Fatalf("Nitro proxy socket mode = %04o, want %04o", got, mode)
			}
			if err := os.Remove(path); err != nil &&
				!errors.Is(err, os.ErrNotExist) {
				t.Fatalf("remove socket: %v", err)
			}
		}
	}
}

func TestListenPrivateUnixRejectsWorldWritableMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nitro.sock")
	listener, err := listenPrivateUnix(path, 0o602)
	if listener != nil {
		_ = listener.Close()
	}
	if err == nil {
		t.Fatal("expected world-writable socket mode to fail")
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected socket was created: %v", statErr)
	}
}
