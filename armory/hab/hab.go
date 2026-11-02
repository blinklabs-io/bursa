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

// Package hab parses what the i.MX6UL/6ULL boot ROM reports through the high
// assurance boot (HAB) API: the ROM vector table header, the configuration
// and state, and the event records. It holds no ROM access; the firmware
// reads the bytes and passes them here.
package hab

import (
	"errors"
	"fmt"
)

const (
	// RVTBase is the address of the HAB ROM vector table on i.MX6UL and
	// i.MX6ULL.
	RVTBase = 0x100

	// RVTHeaderLen is the length of the vector table header.
	RVTHeaderLen = 4

	// OffReportEvent and OffReportStatus are the offsets of the
	// report_event and report_status function pointers in the vector
	// table.
	OffReportEvent  = 0x20
	OffReportStatus = 0x24

	// RVTMinLen is the smallest vector table length that covers
	// report_status.
	RVTMinLen = OffReportStatus + 4

	// StatusAny matches every event status in report_event.
	StatusAny = 0x00

	// StatusSuccess is the status report_event and report_status return
	// on success. report_status also returns StatusWarning or
	// StatusFailure when the event log holds warning or failure events,
	// and still writes the configuration and state.
	StatusSuccess = 0xf0
	StatusWarning = 0x69
	StatusFailure = 0x33

	// eventHeaderLen is the length of an event record header.
	eventHeaderLen = 4

	// ROMEnd is the end of the boot ROM, which holds the HAB functions.
	ROMEnd = 0x20000

	// MaxEvents and MaxEventLen bound what the firmware reads and reports.
	// MaxEventLen matches the buffer U-Boot reads events into: report_event
	// fails on a record larger than the buffer, which ends the log.
	MaxEvents   = 8
	MaxEventLen = 128
)

// ErrNoRVT means the bytes at the vector table address are not a HAB
// vector table header.
var ErrNoRVT = errors.New("hab: RVT not found")

// CheckRVT reports whether hdr is the HAB ROM vector table header: tag 0xdd,
// a big-endian length that covers the entries the firmware calls, and HAB
// major version 4.
func CheckRVT(hdr []byte) error {
	if len(hdr) < RVTHeaderLen {
		return ErrNoRVT
	}

	length := int(hdr[1])<<8 | int(hdr[2])

	if hdr[0] != 0xdd || length < RVTMinLen || hdr[3]>>4 != 4 {
		return ErrNoRVT
	}

	return nil
}

// CheckEntry reports whether ptr, an ARM or Thumb function pointer read from
// the vector table, lies in the boot ROM past the table and is aligned for
// its instruction set (a word for ARM, a halfword for Thumb), so an erased or
// corrupt entry is never jumped to.
func CheckEntry(ptr uint32) bool {
	if ptr&1 == 0 && ptr&3 != 0 {
		return false
	}

	addr := ptr &^ 1 // the Thumb bit

	return addr >= RVTBase+RVTMinLen && addr < ROMEnd
}

func name(names map[uint8]string, v uint8) string {
	if n, ok := names[v]; ok {
		return n
	}

	return fmt.Sprintf("unknown 0x%02x", v)
}

var statusNames = map[uint8]string{
	StatusSuccess: "success",
	StatusWarning: "warning",
	StatusFailure: "failure",
}

var configNames = map[uint8]string{
	0x33: "return",
	0xf0: "open",
	0xcc: "closed",
}

var stateNames = map[uint8]string{
	0x33: "initial",
	0x55: "check",
	0x66: "non-secure",
	0x99: "trusted",
	0xaa: "secure",
	0xcc: "fail-soft",
	0xff: "fail-hard",
	0xf0: "none",
}

// StatusName names a HAB status value.
func StatusName(status uint8) string {
	return name(statusNames, status)
}

// ConfigName names a HAB configuration value.
func ConfigName(config uint8) string {
	return name(configNames, config)
}

// StateName names a HAB state value.
func StateName(state uint8) string {
	return name(stateNames, state)
}

// Report formats the report lines for the report_status result, the
// configuration, the state and the event records read from the ROM, oldest
// first. more means events beyond those given exist.
func Report(status, config, state uint8, events [][]byte, more bool) []string {
	count := "no events"

	switch len(events) {
	case 0:
	case 1:
		count = "1 event"
	default:
		count = fmt.Sprintf("%d events", len(events))
	}

	if more {
		count += ", more not shown"
	}

	lines := make([]string, 0, 1+len(events))
	lines = append(lines, fmt.Sprintf("hab: status %s, config %s, state %s, %s",
		StatusName(status), ConfigName(config), StateName(state), count))

	for i, ev := range events {
		lines = append(lines, formatEvent(i, ev))
	}

	return lines
}

// formatEvent decodes the record header (tag, length, version) and the status,
// reason, context and engine bytes that follow, then the record in hex.
func formatEvent(index int, ev []byte) string {
	if len(ev) < eventHeaderLen+4 {
		return fmt.Sprintf("hab: event %d: short record: %x", index, ev)
	}

	b := ev[eventHeaderLen:]

	return fmt.Sprintf("hab: event %d: status 0x%02x reason 0x%02x context 0x%02x engine 0x%02x: %x",
		index, b[0], b[1], b[2], b[3], ev)
}

// ReadEvents reads the ROM's event log through read, which calls
// report_event for an index and returns the record and whether the ROM
// reported success. The record may share a buffer across calls. Reading stops
// at the first failure, which ends the log; at most MaxEvents records are
// kept, each cut to MaxEventLen, and more reports whether another exists.
func ReadEvents(read func(index uint32) (record []byte, ok bool)) (events [][]byte, more bool) {
	for i := uint32(0); i <= MaxEvents; i++ {
		record, ok := read(i)

		if !ok {
			break
		}

		// one past the cap tells whether more exist
		if i == MaxEvents {
			more = true
			break
		}

		record = record[:min(len(record), MaxEventLen)]
		events = append(events, append([]byte(nil), record...))
	}

	return events, more
}
