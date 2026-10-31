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

package signlog

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// MemMedium is an in-memory Medium.
type MemMedium struct {
	mu  sync.Mutex
	img []byte
}

// NewMemMedium returns a blank medium of the given size in blocks.
func NewMemMedium(blocks uint64) *MemMedium {
	return &MemMedium{img: make([]byte, blocks*BlockSize)}
}

// NewMemMediumFromImage returns a medium holding a copy of img, whose
// length must be a multiple of BlockSize.
func NewMemMediumFromImage(img []byte) (*MemMedium, error) {
	if len(img)%BlockSize != 0 {
		return nil, fmt.Errorf("%w: image of %d bytes is not whole blocks", ErrMedium, len(img))
	}

	return &MemMedium{img: append([]byte(nil), img...)}, nil
}

// Image returns a copy of the medium's contents.
func (m *MemMedium) Image() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]byte(nil), m.img...)
}

// NumBlocks implements Medium.
func (m *MemMedium) NumBlocks() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	return uint64(len(m.img)) / BlockSize
}

func (m *MemMedium) span(lba uint64, n int) (int, error) {
	size := uint64(len(m.img)) //nolint:gosec // slice length is non-negative

	if n%BlockSize != 0 || lba > size/BlockSize || uint64(n) > size-lba*BlockSize { //nolint:gosec // n is a slice length
		return 0, fmt.Errorf("%w: %d bytes at block %d", ErrMedium, n, lba)
	}

	return int(lba * BlockSize), nil //nolint:gosec // bounded by the image length checked above
}

// ReadBlocks implements Medium.
func (m *MemMedium) ReadBlocks(lba uint64, p []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	off, err := m.span(lba, len(p))
	if err != nil {
		return err
	}

	copy(p, m.img[off:])

	return nil
}

// WriteBlocks implements Medium.
func (m *MemMedium) WriteBlocks(lba uint64, p []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	off, err := m.span(lba, len(p))
	if err != nil {
		return err
	}

	copy(m.img[off:], p)

	return nil
}

// Sync implements Medium.
func (m *MemMedium) Sync() error { return nil }

// MemHeadStore is an in-memory HeadStore.
type MemHeadStore struct {
	mu   sync.Mutex
	head Head
}

// NewMemHeadStore returns a store holding head.
func NewMemHeadStore(head Head) *MemHeadStore { return &MemHeadStore{head: head} }

// Load implements HeadStore.
func (s *MemHeadStore) Load() (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.head, nil
}

// Store implements HeadStore.
func (s *MemHeadStore) Store(h Head) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.head = h

	return nil
}

// ReaderMedium is a read-only Medium over a file or block device image.
type ReaderMedium struct {
	r      io.ReaderAt
	blocks uint64
}

// NewReaderMedium returns a read-only medium of size bytes over r. Trailing
// bytes short of a whole block are ignored.
func NewReaderMedium(r io.ReaderAt, size int64) *ReaderMedium {
	return &ReaderMedium{r: r, blocks: uint64(max(size, 0)) / BlockSize}
}

// NumBlocks implements Medium.
func (m *ReaderMedium) NumBlocks() uint64 { return m.blocks }

// ReadBlocks implements Medium.
func (m *ReaderMedium) ReadBlocks(lba uint64, p []byte) error {
	if len(p)%BlockSize != 0 || lba > m.blocks || uint64(len(p)) > (m.blocks-lba)*BlockSize {
		return fmt.Errorf("%w: %d bytes at block %d", ErrMedium, len(p), lba)
	}

	_, err := m.r.ReadAt(p, int64(lba*BlockSize)) //nolint:gosec // bounded by the size checked above

	return err
}

// WriteBlocks implements Medium and always fails.
func (m *ReaderMedium) WriteBlocks(uint64, []byte) error {
	return errors.New("signlog: medium is read-only")
}

// Sync implements Medium and always fails.
func (m *ReaderMedium) Sync() error { return errors.New("signlog: medium is read-only") }
