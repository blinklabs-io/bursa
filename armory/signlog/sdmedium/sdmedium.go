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

// Package sdmedium adapts an SD card driver to signlog.Medium.
//
// Card is the subset of TamaGo's soc/nxp/usdhc USDHC the adapter uses, so
// the adapter runs against a fake card on the host.
//
// Sync semantics. usdhc.WriteBlocks returns once the controller reports
// transfer complete for CMD25 with automatic CMD12; it does not wait for
// the card to finish programming, and it has no flush call. The driver
// polls the card state (CMD13, one millisecond budget) only at the start of
// the next transfer. Sync therefore reads back every block written since the
// previous Sync and compares it with what was written. A read cannot start
// until the card is back in its transfer state, so a matching read means the
// card finished programming and holds the data. It does not force the
// card's internal cache to flash: the SD interface offers no portable flush,
// so the guarantee is that the card acknowledged and returned the data, not
// that it survives a power loss in the next microsecond.
package sdmedium

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa/armory/signlog"
)

var (
	// ErrNoCard is returned when the board has no SD slot or no card is
	// present.
	ErrNoCard = errors.New("sdmedium: no SD card")
	// ErrVerify is returned by Sync when a block reads back different from
	// what was written.
	ErrVerify = errors.New("sdmedium: block reads back differently from what was written")
)

const (
	// syncAttempts and syncPause bound how long Sync waits for a card that
	// is still programming: about two seconds.
	syncAttempts = 200
	syncPause    = 10 * time.Millisecond
)

// Card is an initialised SD card driver.
type Card interface {
	// Detect initialises the card; it is cheap when the card is already
	// initialised and was not removed.
	Detect() error
	// Geometry returns the block size and the number of blocks, valid
	// after Detect succeeds.
	Geometry() (blockSize int, blocks uint64)
	ReadBlocks(lba int, buf []byte) error
	WriteBlocks(lba int, buf []byte) error
}

type pending struct {
	lba  uint64
	data []byte
}

// Medium is a signlog.Medium over a Card.
type Medium struct {
	mu      sync.Mutex
	card    Card
	blocks  uint64
	pending []pending
	sleep   func(time.Duration)
}

// Open detects the card and returns a medium over it. A nil card (a board
// without an SD slot) is ErrNoCard.
func Open(card Card) (*Medium, error) {
	if card == nil {
		return nil, ErrNoCard
	}

	if err := card.Detect(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoCard, err)
	}

	size, blocks := card.Geometry()
	if size != signlog.BlockSize || blocks == 0 {
		return nil, fmt.Errorf("sdmedium: card has %d blocks of %d bytes; need %d-byte blocks", blocks, size, signlog.BlockSize)
	}

	return &Medium{card: card, blocks: blocks, sleep: time.Sleep}, nil
}

// NumBlocks implements signlog.Medium.
func (m *Medium) NumBlocks() uint64 { return m.blocks }

func (m *Medium) check(lba uint64, n int) error {
	if n%signlog.BlockSize != 0 || lba > m.blocks || uint64(n) > (m.blocks-lba)*signlog.BlockSize { //nolint:gosec // n is a slice length
		return fmt.Errorf("%w: %d bytes at block %d", signlog.ErrMedium, n, lba)
	}

	return nil
}

// once runs op and, if it fails, re-detects the card and runs it once more,
// so a card that was reseated or glitched does not wedge the device until
// reboot. Reads and writes of whole blocks are idempotent.
func (m *Medium) once(op func() error) error {
	err := op()
	if err == nil {
		return nil
	}

	if derr := m.card.Detect(); derr != nil {
		return fmt.Errorf("%w; redetect: %w", err, derr)
	}

	return op()
}

// ReadBlocks implements signlog.Medium.
func (m *Medium) ReadBlocks(lba uint64, p []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.check(lba, len(p)); err != nil {
		return err
	}

	if len(p) == 0 {
		return nil
	}

	return m.once(func() error { return m.card.ReadBlocks(int(lba), p) }) //nolint:gosec // lba is below the card's block count
}

// WriteBlocks implements signlog.Medium. The data is durable only after Sync.
func (m *Medium) WriteBlocks(lba uint64, p []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.check(lba, len(p)); err != nil {
		return err
	}

	if len(p) == 0 {
		return nil
	}

	if err := m.once(func() error { return m.card.WriteBlocks(int(lba), p) }); err != nil { //nolint:gosec // lba is below the card's block count
		return err
	}

	m.pending = append(m.pending, pending{lba: lba, data: bytes.Clone(p)})

	return nil
}

// Sync implements signlog.Medium: it reads back what was written since the
// last Sync, waiting for a card that is still programming, and fails if any
// block differs.
func (m *Medium) Sync() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for len(m.pending) > 0 {
		w := m.pending[0]
		got := make([]byte, len(w.data))

		var err error

		for attempt := range syncAttempts {
			if attempt > 0 {
				m.sleep(syncPause)
			}

			if err = m.card.ReadBlocks(int(w.lba), got); err == nil { //nolint:gosec // lba was bounds-checked at write
				break
			}
		}

		if err != nil {
			return fmt.Errorf("sdmedium: card not ready after write: %w", err)
		}

		if !bytes.Equal(got, w.data) {
			return fmt.Errorf("%w: %d blocks at %d", ErrVerify, len(w.data)/signlog.BlockSize, w.lba)
		}

		m.pending = m.pending[1:]
	}

	return nil
}
