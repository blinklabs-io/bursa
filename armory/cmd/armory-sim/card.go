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

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/blinklabs-io/bursa/armory/signlog"
)

// fileCard is an SD card backed by an image file, so the signing log runs
// through the same sdmedium code as on the device and signlog-verify can
// read the image afterwards.
type fileCard struct {
	f      *os.File
	blocks uint64
}

// openCard opens the card image at path, creating a zeroed (sparse) image
// of the given number of blocks if it does not exist.
func openCard(path string, blocks uint64) (*fileCard, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close() //nolint:errcheck,gosec // the stat error is returned
		return nil, err
	}

	if info.Size() == 0 {
		if err := f.Truncate(int64(blocks) * signlog.BlockSize); err != nil { //nolint:gosec // bounded by flag validation
			f.Close() //nolint:errcheck,gosec // the truncate error is returned
			return nil, err
		}

		info, err = f.Stat()
		if err != nil {
			f.Close() //nolint:errcheck,gosec // the stat error is returned
			return nil, err
		}
	}

	size := info.Size()
	if size <= 0 || size%signlog.BlockSize != 0 {
		f.Close() //nolint:errcheck,gosec // the size error is returned
		return nil, fmt.Errorf("card image %s is not a whole number of blocks", path)
	}

	return &fileCard{f: f, blocks: uint64(size / signlog.BlockSize)}, nil
}

func (c *fileCard) Detect() error { return nil }

func (c *fileCard) Geometry() (int, uint64) { return signlog.BlockSize, c.blocks }

func (c *fileCard) check(lba int, buf []byte) error {
	if lba < 0 || len(buf)%signlog.BlockSize != 0 ||
		uint64(lba)+uint64(len(buf)/signlog.BlockSize) > c.blocks {
		return errors.New("card access out of range")
	}

	return nil
}

func (c *fileCard) ReadBlocks(lba int, buf []byte) error {
	if err := c.check(lba, buf); err != nil {
		return err
	}

	_, err := c.f.ReadAt(buf, int64(lba)*signlog.BlockSize)

	return err
}

func (c *fileCard) WriteBlocks(lba int, buf []byte) error {
	if err := c.check(lba, buf); err != nil {
		return err
	}

	if _, err := c.f.WriteAt(buf, int64(lba)*signlog.BlockSize); err != nil {
		return err
	}

	return c.f.Sync()
}
