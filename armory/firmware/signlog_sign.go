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

//go:build !provision

package main

import (
	"sync"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"
	"github.com/usbarmory/tamago/soc/nxp/usdhc"

	"github.com/blinklabs-io/bursa/armory/device"
	"github.com/blinklabs-io/bursa/armory/profile"
	"github.com/blinklabs-io/bursa/armory/signlog"
	"github.com/blinklabs-io/bursa/armory/signlog/chipstore"
	"github.com/blinklabs-io/bursa/armory/signlog/sdmedium"
)

// usdhcCard adapts the uSDHC1 driver to sdmedium.Card.
type usdhcCard struct{ hw *usdhc.USDHC }

func (c usdhcCard) Detect() error { return c.hw.Detect() }

func (c usdhcCard) Geometry() (int, uint64) {
	info := c.hw.Info()

	return info.BlockSize, uint64(max(info.Blocks, 0))
}

func (c usdhcCard) ReadBlocks(lba int, buf []byte) error  { return c.hw.ReadBlocks(lba, buf) }
func (c usdhcCard) WriteBlocks(lba int, buf []byte) error { return c.hw.WriteBlocks(lba, buf) }

// requireSigningLog makes the signing image refuse to sign until the log is
// open. It runs before the endpoints start, so no request can find a device
// that signs without a log.
func requireSigningLog(svc *device.Service) { svc.RequireSigningLog() }

// openSigningLog opens the log on the microSD card against the head in the
// SE050, after the chip is up. Any failure (no slot, no card, an unreadable
// card, a card that does not match the head) leaves the device refusing to
// sign with the reason, while inventory and health are still served.
// lock is the SE050 session lock the endpoints share.
// It reports whether the log is open, so the startup result can fail.
func openSigningLog(r *Report, lock sync.Locker, svc *device.Service, c *chip) bool {
	w, m, err := openLog(lock, c)
	if err != nil {
		r.Logf("signing log: NOT OPEN, signing is refused: %v", err)
		svc.SigningLogFailed(err)

		return false
	}

	svc.SetSigningLog(w, m)

	head := w.Head()
	r.Logf("signing log: open on a %d-block card, head entry %d %x", m.NumBlocks(), head.Seq, head.Hash)

	return true
}

func openLog(lock sync.Locker, c *chip) (*signlog.Writer, *sdmedium.Medium, error) {
	// the LAN model has no SD slot and SD is nil
	var card sdmedium.Card
	if usbarmory.SD != nil {
		card = usdhcCard{usbarmory.SD}
	}

	m, err := sdmedium.Open(card)
	if err != nil {
		return nil, nil, err
	}

	// the chip is shared with the endpoints, which are already serving
	lock.Lock()
	defer lock.Unlock()

	id, err := chipstore.NewIdentity(c, profile.IdentityKeyID)
	if err != nil {
		return nil, nil, err
	}

	w, err := signlog.Open(m, chipstore.NewHeadStore(c, profile.SignLogHeadID), id)
	if err != nil {
		return nil, nil, err
	}

	return w, m, nil
}
