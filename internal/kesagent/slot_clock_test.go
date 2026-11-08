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

package kesagent

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Networks whose Byron era ran 20-second slots count their slots from the
// first Shelley slot; counting 1-second slots from system_start runs ahead
// of the chain.
func TestSlotClockCountsFromTheShelleyAnchor(t *testing.T) {
	now := mustTime(t, "2026-11-08T12:00:00Z")
	for _, tc := range []struct {
		name         string
		systemStart  string
		shelleySlot  uint64
		shelleyStart string
	}{
		{"mainnet", "2017-09-23T21:44:51Z", 4492800, "2020-07-29T21:44:51Z"},
		{"preprod", "2022-06-01T00:00:00Z", 86400, "2022-06-21T00:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cold := newColdKey(t)
			shelleyStart := mustTime(t, tc.shelleyStart)
			a, err := New(Config{
				Mode: ModeSign,
				Profiles: []ProfileConfig{{
					Name:              tc.name,
					SystemStart:       mustTime(t, tc.systemStart),
					ShelleyStartSlot:  tc.shelleySlot,
					ShelleyStartTime:  shelleyStart,
					SlotLength:        time.Second,
					SlotsPerKESPeriod: 129600,
					ColdVKey:          cold.pub,
					GuardPath:         filepath.Join(t.TempDir(), "guard.json"),
				}},
			}, nil, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(a.Close)
			a.now = func() time.Time { return now }
			p := a.profiles[0]

			wantSlot := tc.shelleySlot + uint64(now.Sub(shelleyStart)/time.Second)
			if got := p.currentSlot(); got != wantSlot {
				t.Fatalf("current slot = %d, want %d", got, wantSlot)
			}
			if got, want := p.currentKESPeriod(), wantSlot/129600; got != want {
				t.Fatalf("current KES period = %d, want %d", got, want)
			}
			naive := uint64(now.Sub(mustTime(t, tc.systemStart))/time.Second) / 129600
			if p.currentKESPeriod() == naive {
				t.Fatal("anchored period equals the system_start count; the test does not cover the Byron gap")
			}

			a.now = func() time.Time { return shelleyStart.Add(-time.Hour) }
			if got := p.currentSlot(); got != tc.shelleySlot {
				t.Fatalf("slot before the anchor = %d, want the anchor slot %d", got, tc.shelleySlot)
			}
		})
	}
}

func TestNewRefusesAnIncompleteShelleyAnchor(t *testing.T) {
	cold := newColdKey(t)
	base := ProfileConfig{
		Name:              "p",
		SystemStart:       mustTime(t, "2022-06-01T00:00:00Z"),
		SlotLength:        time.Second,
		SlotsPerKESPeriod: 129600,
		ColdVKey:          cold.pub,
		GuardPath:         filepath.Join(t.TempDir(), "guard.json"),
	}
	slotOnly := base
	slotOnly.ShelleyStartSlot = 86400
	early := base
	early.ShelleyStartTime = mustTime(t, "2022-05-01T00:00:00Z")
	for _, tc := range []struct {
		name string
		pc   ProfileConfig
		want string
	}{
		{"slot without time", slotOnly, "requires shelley_start_time"},
		{"time before system_start", early, "before system_start"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{Mode: ModeSign, Profiles: []ProfileConfig{tc.pc}}, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
