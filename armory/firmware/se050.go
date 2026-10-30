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
	"time"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"
	"github.com/usbarmory/tamago/soc/nxp/i2c"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
	"github.com/usbarmory/tamago/soc/nxp/iomuxc"
)

// SE050 enable line: schematic net SE050_ENA, SoC pad ENET2_TX_DATA1
// (GPIO2_IO12) on UA-MKII-γ.
const (
	IOMUXC_SW_MUX_CTL_PAD_ENET2_TX_DATA1 = 0x020e00f4
	IOMUXC_SW_PAD_CTL_PAD_ENET2_TX_DATA1 = 0x020e0380

	SE050_ENA = 12
	GPIO_MODE = 5
)

// enableSE050 power cycles the SE050 through its enable line.
func enableSE050() error {
	pin, err := imx6ul.GPIO2.Init(SE050_ENA)

	if err != nil {
		return err
	}

	pin.Out()

	iomuxc.Init(
		IOMUXC_SW_MUX_CTL_PAD_ENET2_TX_DATA1,
		IOMUXC_SW_PAD_CTL_PAD_ENET2_TX_DATA1,
		GPIO_MODE)

	pin.Low()
	time.Sleep(10 * time.Millisecond)
	pin.High()
	time.Sleep(100 * time.Millisecond)

	return nil
}

// i2cBus implements se050.Bus with plain transfers, as the SE050 rejects
// register-addressed reads.
type i2cBus struct {
	hw     *i2c.I2C
	target uint8
}

func (b *i2cBus) Write(buf []byte) error {
	return b.hw.Write(buf, b.target, 0, 0)
}

func (b *i2cBus) Read(n int) ([]byte, error) {
	return b.hw.Read(b.target, 0, -1, n)
}

func newSE050Bus() *i2cBus {
	return &i2cBus{
		hw:     usbarmory.I2C1,
		target: usbarmory.SE050_ADDR,
	}
}
