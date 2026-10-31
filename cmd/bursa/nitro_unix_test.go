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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestListenPrivateUnixNeverPublishesPermissiveMode(t *testing.T) {
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	dir := t.TempDir()
	for i := range 256 {
		path := filepath.Join(dir, fmt.Sprintf("nitro-%d.sock", i))
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
				if info, err := os.Lstat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
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

		listener, err := listenPrivateUnix(path)
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
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove socket: %v", err)
		}
	}
}
