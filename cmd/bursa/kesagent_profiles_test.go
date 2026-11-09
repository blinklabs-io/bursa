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
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/kesagent"
)

const testColdVKeyHex = "5820" +
	"0101010101010101010101010101010101010101010101010101010101010101"

func TestKESAgentProfilesFromSinglePoolFields(t *testing.T) {
	got, err := kesAgentProfiles(config.KESAgentConfig{
		ColdVKeyHex:       testColdVKeyHex,
		SystemStart:       "2022-10-25T00:00:00Z",
		SlotLength:        1,
		SlotsPerKESPeriod: 129600,
		MaxKESEvolutions:  62,
		GuardFile:         "/var/lib/bursa/guard.json",
	})
	if err != nil {
		t.Fatalf("kesAgentProfiles: %v", err)
	}
	if len(got) != 1 || got[0].Name != kesagent.DefaultProfileName ||
		got[0].GuardPath != "/var/lib/bursa/guard.json" ||
		got[0].SlotLength != time.Second || len(got[0].ColdVKey) != 32 {
		t.Fatalf("profiles = %+v", got)
	}
}

func TestKESAgentProfilesList(t *testing.T) {
	got, err := kesAgentProfiles(config.KESAgentConfig{
		SlotLength:       1, // the config default, set on every load
		MaxKESEvolutions: 62,
		Profiles: []config.KESAgentProfileConfig{
			{
				Name:              "mainnet-pool",
				ColdVKeyHex:       testColdVKeyHex,
				SystemStart:       "2017-09-23T21:44:51Z",
				SlotsPerKESPeriod: 129600,
				GuardFile:         "/var/lib/bursa/mainnet.json",
			},
			{
				Name:              "preview-pool",
				ColdVKeyHex:       testColdVKeyHex,
				SystemStart:       "2022-10-25T00:00:00Z",
				SlotLength:        2,
				SlotsPerKESPeriod: 129600,
				GuardFile:         "/var/lib/bursa/preview.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("kesAgentProfiles: %v", err)
	}
	if len(got) != 2 || got[0].SlotLength != time.Second ||
		got[1].SlotLength != 2*time.Second || got[1].Name != "preview-pool" {
		t.Fatalf("profiles = %+v", got)
	}
}

func TestKESAgentProfilesRefusesMixedOrIncompleteConfig(t *testing.T) {
	complete := config.KESAgentProfileConfig{
		Name:              "pool",
		ColdVKeyHex:       testColdVKeyHex,
		SystemStart:       "2022-10-25T00:00:00Z",
		SlotsPerKESPeriod: 129600,
		GuardFile:         "/var/lib/bursa/pool.json",
	}
	noStart := complete
	noStart.SystemStart = ""
	for _, tc := range []struct {
		name string
		kc   config.KESAgentConfig
		want string
	}{
		{
			name: "profiles and single-pool fields",
			kc: config.KESAgentConfig{
				GuardFile: "/var/lib/bursa/guard.json",
				Profiles:  []config.KESAgentProfileConfig{complete},
			},
			want: "kes_agent.profiles replaces",
		},
		{
			name: "profile without system_start",
			kc: config.KESAgentConfig{
				Profiles: []config.KESAgentProfileConfig{complete, noStart},
			},
			want: "kes_agent.profiles[1].system_start",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kesAgentProfiles(tc.kc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestKESAgentProfilesRefusesTopLevelSchedule verifies that a top-level
// slot_length or max_kes_evolutions other than the config default is refused
// with profiles rather than silently replaced by each profile's own value.
func TestKESAgentProfilesRefusesTopLevelSchedule(t *testing.T) {
	pc := config.KESAgentProfileConfig{
		Name:              "pool",
		ColdVKeyHex:       testColdVKeyHex,
		SystemStart:       "2022-10-25T00:00:00Z",
		SlotsPerKESPeriod: 129600,
		GuardFile:         "/var/lib/bursa/pool.json",
	}
	for _, tc := range []struct {
		name             string
		slotLength       float64
		maxKESEvolutions uint64
	}{
		{name: "slot_length", slotLength: 2, maxKESEvolutions: 62},
		{name: "max_kes_evolutions", slotLength: 1, maxKESEvolutions: 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kesAgentProfiles(config.KESAgentConfig{
				SlotLength:       tc.slotLength,
				MaxKESEvolutions: tc.maxKESEvolutions,
				Profiles:         []config.KESAgentProfileConfig{pc},
			})
			if err == nil ||
				!strings.Contains(err.Error(), "replaces slot_length and max_kes_evolutions") {
				t.Fatalf("err = %v, want a refusal", err)
			}
		})
	}
}
