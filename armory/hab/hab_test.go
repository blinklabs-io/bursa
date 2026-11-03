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

	statuses := map[uint8]string{
		0xf0: "success",
		0x69: "warning",
		0x33: "failure",
		0x00: "unknown 0x00",
	}

	for v, want := range statuses {
		if got := StatusName(v); got != want {
			t.Errorf("StatusName(%#02x) = %q, want %q", v, got, want)
		}
	}
}

func TestCheckStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status uint32
		config uint8
		state  uint8
		ok     bool
	}{
		{"success, open, non-secure", 0xf0, 0xf0, 0x66, true},
		{"warning, open, non-secure", 0x69, 0xf0, 0x66, true},
		{"failure, closed, fail-soft", 0x33, 0xcc, 0xcc, true},
		{"status not a HAB status", 0x00, 0xf0, 0x66, false},
		{"status with upper bits set", 0x1f0, 0xf0, 0x66, false},
		{"configuration never written", 0x33, 0x00, 0x66, false},
		{"state never written", 0x33, 0xf0, 0x00, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := CheckStatus(tc.status, tc.config, tc.state)

			if tc.ok && err != nil {
				t.Fatalf("CheckStatus(%#x, %#x, %#x) = %v, want nil", tc.status, tc.config, tc.state, err)
			}

			if !tc.ok && !errors.Is(err, ErrStatus) {
				t.Fatalf("CheckStatus(%#x, %#x, %#x) = %v, want ErrStatus", tc.status, tc.config, tc.state, err)
			}
		})
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
		status uint8
		config uint8
		state  uint8
		events [][]byte
		more   bool
		want   []string
	}{
		{
			name:   "open unfused, no events",
			status: 0xf0, config: 0xf0, state: 0x66,
			want: []string{"hab: status success, config open, state non-secure, no events"},
		},
		{
			name:   "closed and trusted",
			status: 0xf0, config: 0xcc, state: 0x99,
			want: []string{"hab: status success, config closed, state trusted, no events"},
		},
		{
			name:   "one event",
			status: 0x33, config: 0xf0, state: 0x66,
			events: [][]byte{ev1},
			want: []string{
				"hab: status failure, config open, state non-secure, 1 event",
				"hab: event 0: status 0x33 reason 0x0c context 0xa0 engine 0x00: db000842330ca000",
			},
		},
		{
			name:   "two events with data",
			status: 0x33, config: 0xf0, state: 0x66,
			events: [][]byte{ev1, ev2},
			want: []string{
				"hab: status failure, config open, state non-secure, 2 events",
				"hab: event 0: status 0x33 reason 0x0c context 0xa0 engine 0x00: db000842330ca000",
				"hab: event 1: status 0x33 reason 0x1e context 0xc0 engine 0x1b: db000c42331ec01bdeadbeef",
			},
		},
		{
			name:   "events beyond the cap",
			status: 0x33, config: 0xf0, state: 0x66,
			events: [][]byte{ev1},
			more:   true,
			want: []string{
				"hab: status failure, config open, state non-secure, 1 event, more not shown",
				"hab: event 0: status 0x33 reason 0x0c context 0xa0 engine 0x00: db000842330ca000",
			},
		},
		{
			name:   "truncated record",
			status: 0x33, config: 0xf0, state: 0x66,
			events: [][]byte{{0xdb, 0x00, 0x08}},
			want: []string{
				"hab: status failure, config open, state non-secure, 1 event",
				"hab: event 0: short record: db0008",
			},
		},
		{
			name:   "unknown status, config and state",
			status: 0x01, config: 0x00, state: 0x01,
			want: []string{"hab: status unknown 0x01, config unknown 0x00, state unknown 0x01, no events"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := Report(tc.status, tc.config, tc.state, tc.events, tc.more)

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
		{"Thumb function at a halfword", 0x00001003, true},
		{"ARM function at a halfword", 0x00001002, false},
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

// romLog stands in for report_event: it returns the records in order, then
// fails, and writes every record into one buffer as the ROM does.
type romLog struct {
	records [][]byte
	buf     [MaxEventLen + 16]byte
	calls   []uint32
}

func (l *romLog) read(index uint32) ([]byte, bool) {
	l.calls = append(l.calls, index)

	if int(index) >= len(l.records) {
		return nil, false
	}

	n := copy(l.buf[:], l.records[index])

	return l.buf[:n], true
}

func records(n int) [][]byte {
	out := make([][]byte, n)

	for i := range out {
		out[i] = []byte{0xdb, 0x00, 0x08, 0x42, 0x33, byte(i), 0xa0, 0x00}
	}

	return out
}

func TestReadEvents(t *testing.T) {
	t.Parallel()

	long := make([]byte, MaxEventLen+8)
	for i := range long {
		long[i] = byte(i)
	}

	tests := []struct {
		name    string
		records [][]byte
		want    [][]byte
		more    bool
		calls   int
	}{
		{"empty log", nil, nil, false, 1},
		{"two records", records(2), records(2), false, 3},
		{"exactly the cap", records(MaxEvents), records(MaxEvents), false, MaxEvents + 1},
		{"one past the cap", records(MaxEvents + 1), records(MaxEvents), true, MaxEvents + 1},
		{"far past the cap", records(3 * MaxEvents), records(MaxEvents), true, MaxEvents + 1},
		{"record longer than the cap", [][]byte{long}, [][]byte{long[:MaxEventLen]}, false, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := &romLog{records: tc.records}

			got, more := ReadEvents(l.read)

			if !reflect.DeepEqual(got, tc.want) || more != tc.more {
				t.Fatalf("ReadEvents() = %x, %v, want %x, %v", got, more, tc.want, tc.more)
			}

			if len(l.calls) != tc.calls {
				t.Fatalf("report_event called for %v, want %d calls", l.calls, tc.calls)
			}

			for i, idx := range l.calls {
				if idx != uint32(i) {
					t.Fatalf("report_event called for %v, want indexes from 0", l.calls)
				}
			}
		})
	}
}
