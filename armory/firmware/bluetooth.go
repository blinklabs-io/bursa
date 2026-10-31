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
	"github.com/usbarmory/tamago/bits"
	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"
	"github.com/usbarmory/tamago/soc/nxp/gpio"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
	"github.com/usbarmory/tamago/soc/nxp/iomuxc"

	"github.com/blinklabs-io/bursa/armory/ble"
)

// btReset is the ANNA-B112's RESET_N (GPIO1_IO09), active low. TamaGo's
// ANNA.Init releases it, so the firmware drives the pin itself and never
// calls Init.
type btReset struct {
	pin *gpio.Pin
}

func (b *btReset) Claim() (err error) {
	b.pin, err = imx6ul.GPIO1.Init(usbarmory.BT_RESET)
	return
}

func (b *btReset) Low() { b.pin.Low() }

func (b *btReset) GPIOMode() {
	var ctl uint32

	// a pad control value of zero disables the output driver
	bits.SetN(&ctl, iomuxc.SW_PAD_CTL_DSE, 0b111, iomuxc.SW_PAD_CTL_DSE_2_R0_4)
	bits.SetN(&ctl, iomuxc.SW_PAD_CTL_SPEED, 0b11, iomuxc.SW_PAD_CTL_SPEED_50MHZ)

	p := iomuxc.Init(
		usbarmory.IOMUXC_SW_MUX_CTL_PAD_GPIO1_IO09,
		usbarmory.IOMUXC_SW_PAD_CTL_PAD_GPIO1_IO09,
		usbarmory.GPIO_MODE)
	p.Ctl(ctl)
}

func (b *btReset) Out() { b.pin.Out() }

func (b *btReset) High() bool { return b.pin.Value() }

// holdBluetooth holds the Bluetooth module in reset for the life of the
// firmware and reports the outcome. The module's SWITCH pins are left alone:
// they only select a boot mode as the module leaves reset.
func holdBluetooth(r *Report) {
	if err := ble.HoldInReset(&btReset{}); err != nil {
		r.Logf("bluetooth: cannot hold module in reset: %v", err)
		r.fail()
		return
	}

	r.Logf("bluetooth: module held in reset")
}
