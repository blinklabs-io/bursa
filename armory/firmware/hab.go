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
	"unsafe"

	"github.com/usbarmory/tamago/arm"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"

	"github.com/blinklabs-io/bursa/armory/hab"
)

// Implemented in hab_arm.s.

// habCall calls the ARM or Thumb function at fn with r0-r3 as its arguments
// under the AAPCS and returns its r0, with interrupts masked and the stack
// 8-byte aligned.
func habCall(fn, r0, r1, r2, r3 uint32) uint32

func habRead32(addr uint32) uint32
func habWrite32(addr, val uint32)

// habTTBR0 returns the translation table base register.
func habTTBR0() uint32

// The ROM writes through these, so they are statics the runtime does not
// move, word-aligned.
var (
	habConfigState [2]uint32
	habEventLen    uint32
	habEventBuf    [hab.MaxEventLen / 4]uint32
)

func habEvent() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&habEventBuf[0])), hab.MaxEventLen)
}

// habStackGuard grows the goroutine stack ahead of the ROM calls, which run
// on it without the runtime's stack checks. The loop keeps the compiler from
// folding pad away, so the 4 KiB frame and its stack check stay in the
// function.
//
//go:noinline
func habStackGuard(fill byte) byte {
	var pad [4096]byte

	for i := range pad {
		pad[i] = fill
	}

	return pad[len(pad)-1]
}

// romCall grows the stack and calls the ROM with nothing in between that
// could let the runtime shrink it again.
func romCall(fn, r0, r1, r2, r3 uint32) uint32 {
	habStackGuard(1)

	return habCall(fn, r0, r1, r2, r3)
}

func addr(p *uint32) uint32 {
	return uint32(uintptr(unsafe.Pointer(p)))
}

// habStatus reads the HAB configuration, state and events from the boot ROM
// through its vector table. It calls only the report functions, which change
// nothing. The ROM is unmapped (and not executable) in the runtime's
// translation table, so the first megabyte is mapped for the calls and the
// original entry restored after.
func habStatus() (status, config, state uint8, events [][]byte, more bool, err error) {
	table := habTTBR0() &^ 0x3fff
	saved := habRead32(table)

	imx6ul.ARM.ConfigureMMU(0, 1<<20, 0, arm.MemoryRegion)

	defer func() {
		habWrite32(table, saved)
		imx6ul.ARM.FlushDataCache()
		imx6ul.ARM.FlushTLBs()
	}()

	var hdr [hab.RVTHeaderLen]byte

	word := habRead32(hab.RVTBase)
	hdr[0], hdr[1], hdr[2], hdr[3] = byte(word), byte(word>>8), byte(word>>16), byte(word>>24)

	if err = hab.CheckRVT(hdr[:]); err != nil {
		return
	}

	reportEvent := habRead32(hab.RVTBase + hab.OffReportEvent)
	reportStatus := habRead32(hab.RVTBase + hab.OffReportStatus)

	if !hab.CheckEntry(reportEvent) || !hab.CheckEntry(reportStatus) {
		err = hab.ErrNoRVT
		return
	}

	// a warning or failure status still reports the configuration and
	// state; the status is reported with them
	ret := romCall(reportStatus, addr(&habConfigState[0]), addr(&habConfigState[1]), 0, 0)
	config, state = uint8(habConfigState[0]), uint8(habConfigState[1])

	if err = hab.CheckStatus(ret, config, state); err != nil {
		return
	}

	status = uint8(ret)

	events, more = hab.ReadEvents(func(index uint32) ([]byte, bool) {
		habEventLen = hab.MaxEventLen

		if romCall(reportEvent, hab.StatusAny, index, addr(&habEventBuf[0]), addr(&habEventLen)) != hab.StatusSuccess {
			return nil, false
		}

		return habEvent()[:min(habEventLen, hab.MaxEventLen)], true
	})

	return
}

// reportHAB adds the boot ROM's HAB status and events to the report. On a
// board whose fuses are not burnt the ROM runs an image whatever its
// signature, and the events are the only sign of whether it verified.
func reportHAB(r *Report) {
	status, config, state, events, more, err := habStatus()

	if err != nil {
		r.Logf("%v", err)
		return
	}

	for _, line := range hab.Report(status, config, state, events, more) {
		r.Logf("%s", line)
	}
}
