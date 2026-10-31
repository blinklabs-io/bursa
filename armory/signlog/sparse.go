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
)

// SparseMedium is a read-only Medium of a given size whose first blocks are
// held in memory and whose remaining blocks read as zero. A host that
// fetched only the used prefix of a card verifies it with it: the card's
// unused slots are blank by the device's own head.
type SparseMedium struct {
	blocks uint64
	prefix []byte
}

// NewSparseMedium returns a medium of blocks blocks starting with prefix,
// whose length must be whole blocks and no longer than the medium.
func NewSparseMedium(blocks uint64, prefix []byte) (*SparseMedium, error) {
	if len(prefix)%BlockSize != 0 || uint64(len(prefix))/BlockSize > blocks {
		return nil, fmt.Errorf("%w: prefix of %d bytes for a medium of %d blocks", ErrMedium, len(prefix), blocks)
	}

	return &SparseMedium{blocks: blocks, prefix: append([]byte(nil), prefix...)}, nil
}

// NumBlocks implements Medium.
func (m *SparseMedium) NumBlocks() uint64 { return m.blocks }

// ReadBlocks implements Medium.
func (m *SparseMedium) ReadBlocks(lba uint64, p []byte) error {
	if len(p)%BlockSize != 0 || lba > m.blocks || uint64(len(p)) > (m.blocks-lba)*BlockSize {
		return fmt.Errorf("%w: %d bytes at block %d", ErrMedium, len(p), lba)
	}

	clear(p)

	if size := uint64(len(m.prefix)); lba*BlockSize < size {
		copy(p, m.prefix[lba*BlockSize:])
	}

	return nil
}

// WriteBlocks implements Medium and always fails.
func (m *SparseMedium) WriteBlocks(uint64, []byte) error {
	return errors.New("signlog: medium is read-only")
}

// Sync implements Medium and always fails.
func (m *SparseMedium) Sync() error { return errors.New("signlog: medium is read-only") }
