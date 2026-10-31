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

package ble_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/blinklabs-io/bursa/armory/ble"
)

// fakeLine records the calls HoldInReset makes. It has no High method, so a
// regression that drives the line high cannot compile against ble.Line.
type fakeLine struct {
	calls     []string
	level     bool
	claimErr  error
	stuckHigh bool
}

func (f *fakeLine) Claim() error {
	f.calls = append(f.calls, "claim")
	return f.claimErr
}

func (f *fakeLine) Low() {
	f.calls = append(f.calls, "low")
	f.level = false
}

func (f *fakeLine) GPIOMode() { f.calls = append(f.calls, "gpio-mode") }

func (f *fakeLine) Out() { f.calls = append(f.calls, "out") }

func (f *fakeLine) High() bool { return f.stuckHigh }

func TestHoldInResetSequence(t *testing.T) {
	t.Parallel()

	f := &fakeLine{}

	if err := ble.HoldInReset(f); err != nil {
		t.Fatalf("HoldInReset: %v", err)
	}

	// the level is latched low before the pin drives, so the line never
	// glitches high when it becomes an output
	want := []string{"claim", "low", "gpio-mode", "out"}

	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
}

func TestHoldInResetClaimFailure(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	f := &fakeLine{claimErr: boom}

	err := ble.HoldInReset(f)

	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}

	if !slices.Equal(f.calls, []string{"claim"}) {
		t.Fatalf("calls after claim failure = %v, want only claim", f.calls)
	}
}

func TestHoldInResetDetectsLineNotLow(t *testing.T) {
	t.Parallel()

	f := &fakeLine{stuckHigh: true}

	if err := ble.HoldInReset(f); err == nil {
		t.Fatal("HoldInReset succeeded with the line reading high")
	}
}
