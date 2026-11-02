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

package hab

import (
	"errors"
	"reflect"
	"testing"
)

func TestCheckRVT(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hdr  []byte
		ok   bool
	}{
		{"HAB 4.0 table", []byte{0xdd, 0x00, 0x30, 0x40}, true},
		{"HAB 4.1 table", []byte{0xdd, 0x00, 0x30, 0x41}, true},
		{"length exactly covers report_status", []byte{0xdd, 0x00, 0x28, 0x40}, true},
		{"erased", []byte{0xff, 0xff, 0xff, 0xff}, false},
		{"zero", []byte{0, 0, 0, 0}, false},
		{"event tag", []byte{0xdb, 0x00, 0x30, 0x40}, false},
		{"length one short", []byte{0xdd, 0x00, 0x27, 0x40}, false},
		{"HAB 3", []byte{0xdd, 0x00, 0x30, 0x30}, false},
		{"HAB 5", []byte{0xdd, 0x00, 0x30, 0x50}, false},
		{"short", []byte{0xdd, 0x00, 0x30}, false},
		{"nil", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := CheckRVT(tc.hdr)

			if tc.ok && err != nil {
				t.Fatalf("CheckRVT(% x) = %v, want nil", tc.hdr, err)
			}

			if !tc.ok && !errors.Is(err, ErrNoRVT) {
				t.Fatalf("CheckRVT(% x) = %v, want ErrNoRVT", tc.hdr, err)
			}
		})
	}
}

func TestNames(t *testing.T) {
	t.Parallel()

	configs := map[uint8]string{
		0x33: "return",
		0xf0: "open",
		0xcc: "closed",
		0x00: "unknown 0x00",
	}

	for v, want := range configs {
		if got := ConfigName(v); got != want {
			t.Errorf("ConfigName(%#02x) = %q, want %q", v, got, want)
		}
	}

	states := map[uint8]string{
		0x33: "initial",
		0x55: "check",
		0x66: "non-secure",
		0x99: "trusted",
		0xaa: "secure",
		0xcc: "fail-soft",
		0xff: "fail-hard",
		0xf0: "none",
		0x01: "unknown 0x01",
	}

	for v, want := range states {
		if got := StateName(v); got != want {
			t.Errorf("StateName(%#02x) = %q, want %q", v, got, want)
		}
	}
}

func TestReport(t *testing.T) {
	t.Parallel()

	// header (tag 0xdb, length 8, version 0x42), status, reason, context,
	// engine
	ev1 := []byte{0xdb, 0x00, 0x08, 0x42, 0x33, 0x0c, 0xa0, 0x00}
	ev2 := []byte{0xdb, 0x00, 0x0c, 0x42, 0x33, 0x1e, 0xc0, 0x1b, 0xde, 0xad, 0xbe, 0xef}

	tests := []struct {
		name   string
		config uint8
		state  uint8
		events [][]byte
		more   bool
		want   []string
	}{
		{
			name:   "open unfused, no events",
			config: 0xf0, state: 0x66,
			want: []string{"hab: config open, state non-secure, no events"},
		},
		{
			name:   "closed and trusted",
			config: 0xcc, state: 0x99,
			want: []string{"hab: config closed, state trusted, no events"},
		},
		{
			name:   "one event",
			config: 0xf0, state: 0x66,
			events: [][]byte{ev1},
			want: []string{
				"hab: config open, state non-secure, 1 event",
				"hab: event 0: status 0x33 reason 0x0c context 0xa0 engine 0x00: db000842330ca000",
			},
		},
		{
			name:   "two events with data",
			config: 0xf0, state: 0x66,
			events: [][]byte{ev1, ev2},
			want: []string{
				"hab: config open, state non-secure, 2 events",
				"hab: event 0: status 0x33 reason 0x0c context 0xa0 engine 0x00: db000842330ca000",
				"hab: event 1: status 0x33 reason 0x1e context 0xc0 engine 0x1b: db000c42331ec01bdeadbeef",
			},
		},
		{
			name:   "events beyond the cap",
			config: 0xf0, state: 0x66,
			events: [][]byte{ev1},
			more:   true,
			want: []string{
				"hab: config open, state non-secure, 1 event, more not shown",
				"hab: event 0: status 0x33 reason 0x0c context 0xa0 engine 0x00: db000842330ca000",
			},
		},
		{
			name:   "truncated record",
			config: 0xf0, state: 0x66,
			events: [][]byte{{0xdb, 0x00, 0x08}},
			want: []string{
				"hab: config open, state non-secure, 1 event",
				"hab: event 0: short record: db0008",
			},
		},
		{
			name:   "unknown config and state",
			config: 0x00, state: 0x01,
			want: []string{"hab: config unknown 0x00, state unknown 0x01, no events"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := Report(tc.config, tc.state, tc.events, tc.more)

			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Report() =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

func TestCheckEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ptr  uint32
		ok   bool
	}{
		{"ARM function in ROM", 0x00001000, true},
		{"Thumb function in ROM", 0x00001001, true},
		{"last ROM word", 0x0001fffc, true},
		{"erased", 0xffffffff, false},
		{"zero", 0, false},
		{"inside the vector table", 0x00000110, false},
		{"first byte past ROM", 0x00020000, false},
		{"RAM", 0x80010000, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := CheckEntry(tc.ptr); got != tc.ok {
				t.Fatalf("CheckEntry(%#x) = %v, want %v", tc.ptr, got, tc.ok)
			}
		})
	}
}
