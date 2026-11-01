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

// Package ble holds the USB armory Mk II's Bluetooth module in reset.
package ble

import (
	"errors"
	"fmt"
)

// Line is the module's active-low RESET_N pin. It has no method that drives
// the line high: the firmware never releases the module.
type Line interface {
	// Claim readies the pin's GPIO controller.
	Claim() error
	// Low latches the output level low.
	Low()
	// GPIOMode muxes the pad to GPIO and sets its drive strength.
	GPIOMode()
	// Out makes the pin an output, which drives the latched level.
	Out()
	// ReadsHigh reports whether the pad reads high, as the pin's input sees
	// it rather than the latched output level.
	ReadsHigh() bool
}

// HoldInReset drives the line low, which holds the module in reset.
//
// The level is latched before the pin becomes an output so the line never
// glitches high. It returns an error if the pad does not read low.
func HoldInReset(l Line) error {
	if err := l.Claim(); err != nil {
		return fmt.Errorf("claim BT_RESET: %w", err)
	}

	l.Low()
	l.GPIOMode()
	l.Out()

	if l.ReadsHigh() {
		return errors.New("BT_RESET reads high")
	}

	return nil
}
