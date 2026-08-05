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

// Package securemem provides a pure-Go locked byte buffer for holding
// sensitive key material off the garbage-collected heap where possible.
//
// The buffer is backed by a byte slice that is pinned into physical memory
// with mlock(2) on supported Unix platforms so it is never written to swap.
// On platforms without mlock (or when mlock is refused, e.g. a low
// RLIMIT_MEMLOCK), New falls back to an ordinary buffer and records that the
// memory could not be locked; callers can surface a warning. The KES agent is
// Linux-only in practice, so the fallback exists only to keep builds and tests
// green on other platforms.
//
// This package uses only the standard library (syscall) — no cgo/libsodium.
package securemem

import (
	"errors"
	"runtime"
	"sync"
)

// ErrClosed is returned when operating on a buffer that has been closed.
var ErrClosed = errors.New("securemem: buffer is closed")

// Buffer is a fixed-size byte buffer whose backing memory is locked into RAM
// (mlock) when the platform allows it. All methods are safe for concurrent
// use. The zero value is not usable; construct one with New.
type Buffer struct {
	mu     sync.Mutex
	data   []byte
	locked bool // true if the backing memory is mlock'd
	closed bool
}

// New allocates a locked buffer of the given size. It never fails on the
// memory-locking step: if mlock is unsupported or refused, the returned buffer
// is usable but not locked and Locked reports false. It returns an error only
// for an invalid size.
func New(size int) (*Buffer, error) {
	if size <= 0 {
		return nil, errors.New("securemem: size must be positive")
	}
	data := make([]byte, size)
	locked := lockMemory(data) == nil
	b := &Buffer{data: data, locked: locked}
	return b, nil
}

// Locked reports whether the backing memory is pinned with mlock.
func (b *Buffer) Locked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.locked
}

// Len returns the buffer size, or 0 once closed.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0
	}
	return len(b.data)
}

// Set copies src into the buffer. src must be exactly the buffer size.
func (b *Buffer) Set(src []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	if len(src) != len(b.data) {
		return errors.New("securemem: source length does not match buffer size")
	}
	copy(b.data, src)
	return nil
}

// Bytes returns the underlying slice. The caller must not retain the slice
// beyond the lifetime of the buffer and must not mutate it except through
// Set/Zeroize. It is exposed so key material can be handed to signing routines
// without an intermediate heap copy.
func (b *Buffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	return b.data
}

// Clone returns a heap copy of the buffer contents. Callers should Wipe the
// returned slice when done. Used only where an API requires an owned slice.
func (b *Buffer) Clone() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	out := make([]byte, len(b.data))
	copy(out, b.data)
	return out
}

// Zeroize wipes the buffer contents to zero. The buffer remains usable.
func (b *Buffer) Zeroize() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	Wipe(b.data)
}

// Close wipes the buffer, unlocks the memory, and marks it unusable. It is
// idempotent.
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	Wipe(b.data)
	var err error
	if b.locked {
		err = unlockMemory(b.data)
		b.locked = false
	}
	b.data = nil
	b.closed = true
	return err
}

// Wipe overwrites b with zeros. It is written so the compiler cannot elide the
// clear: the KeepAlive keeps the slice live across the loop.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(&b)
}
