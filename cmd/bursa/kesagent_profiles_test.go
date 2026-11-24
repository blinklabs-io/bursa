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

func TestKESAgentProfilesParsesTheShelleyAnchor(t *testing.T) {
	got, err := kesAgentProfiles(config.KESAgentConfig{
		ColdVKeyHex:       testColdVKeyHex,
		SystemStart:       "2022-06-01T00:00:00Z",
		ShelleyStartSlot:  86400,
		ShelleyStartTime:  "2022-06-21T00:00:00Z",
		SlotLength:        1,
		SlotsPerKESPeriod: 129600,
		GuardFile:         "/var/lib/bursa/guard.json",
	})
	if err != nil {
		t.Fatalf("kesAgentProfiles: %v", err)
	}
	if got[0].ShelleyStartSlot != 86400 ||
		!got[0].ShelleyStartTime.Equal(time.Date(2022, 6, 21, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("anchor = %d %v", got[0].ShelleyStartSlot, got[0].ShelleyStartTime)
	}
	_, err = kesAgentProfiles(config.KESAgentConfig{
		ColdVKeyHex:       testColdVKeyHex,
		SystemStart:       "2022-06-01T00:00:00Z",
		ShelleyStartTime:  "June 21",
		SlotLength:        1,
		SlotsPerKESPeriod: 129600,
	})
	if err == nil || !strings.Contains(err.Error(), "shelley_start_time must be RFC3339") {
		t.Fatalf("bad shelley_start_time: err = %v", err)
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

func TestKESAgentProfilesParsesMaxClockSkew(t *testing.T) {
	kc := config.KESAgentConfig{
		ColdVKeyHex:       testColdVKeyHex,
		SystemStart:       "2022-10-25T00:00:00Z",
		SlotLength:        1,
		SlotsPerKESPeriod: 129600,
		MaxClockSkew:      "2s",
		GuardFile:         "/var/lib/bursa/guard.json",
	}
	got, err := kesAgentProfiles(kc)
	if err != nil {
		t.Fatalf("kesAgentProfiles: %v", err)
	}
	if got[0].MaxClockSkew != 2*time.Second {
		t.Fatalf("max_clock_skew = %v, want 2s", got[0].MaxClockSkew)
	}
	for _, bad := range []string{"soon", "0s", "-1s"} {
		kc.MaxClockSkew = bad
		if _, err := kesAgentProfiles(kc); err == nil ||
			!strings.Contains(err.Error(), "max_clock_skew") {
			t.Fatalf("max_clock_skew %q: err = %v, want a refusal", bad, err)
		}
	}
}

const testControlSPKI = "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b"

func controlConfig() config.KESAgentConfig {
	return config.KESAgentConfig{
		ColdVKeyHex:             testColdVKeyHex,
		SystemStart:             "2022-10-25T00:00:00Z",
		SlotLength:              1,
		SlotsPerKESPeriod:       129600,
		MaxKESEvolutions:        62,
		GuardFile:               "/var/lib/bursa/guard.json",
		ControlClientSPKISHA256: []string{testControlSPKI},
		AttestedListenAddress:   "127.0.0.1:0",
		AttestedClientCAFile:    "/etc/bursa/clients.pem",
	}
}

func signConfig() config.KESAgentConfig {
	kc := controlConfig()
	kc.ControlClientSPKISHA256 = nil
	kc.SignClientSPKISHA256 = []string{testControlSPKI}
	return kc
}

func TestKESAgentProfilesControlListNeedsClientCertVerification(t *testing.T) {
	t.Parallel()
	ok, err := kesAgentProfiles(controlConfig())
	if err != nil {
		t.Fatalf("control list with a client CA: %v", err)
	}
	if len(ok) != 1 || len(ok[0].ControlClientSPKI) != 1 {
		t.Fatalf("control list not carried to the profile: %+v", ok)
	}
	for name, mutate := range map[string]func(*config.KESAgentConfig){
		"plaintext": func(kc *config.KESAgentConfig) {
			kc.AttestedPlaintext = true
			kc.AttestedClientCAFile = ""
		},
		"no client CA": func(kc *config.KESAgentConfig) {
			kc.AttestedClientCAFile = ""
		},
		"no attested listener": func(kc *config.KESAgentConfig) {
			kc.AttestedListenAddress = ""
		},
		"profile list without client CA": func(kc *config.KESAgentConfig) {
			kc.ControlClientSPKISHA256 = nil
			kc.AttestedClientCAFile = ""
			kc.Profiles = []config.KESAgentProfileConfig{{
				Name:                    "pool",
				ColdVKeyHex:             testColdVKeyHex,
				SystemStart:             "2022-10-25T00:00:00Z",
				SlotsPerKESPeriod:       129600,
				GuardFile:               "/var/lib/bursa/guard.json",
				ControlClientSPKISHA256: []string{testControlSPKI},
			}}
			kc.ColdVKeyHex, kc.SystemStart, kc.SlotsPerKESPeriod, kc.GuardFile = "", "", 0, ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			kc := controlConfig()
			mutate(&kc)
			_, err := kesAgentProfiles(kc)
			if err == nil || !strings.Contains(err.Error(), "control_client_spki_sha256") {
				t.Fatalf("err = %v, want a control_client_spki_sha256 refusal", err)
			}
		})
	}
}

func TestKESAgentProfilesRefusesMalformedControlSPKI(t *testing.T) {
	t.Parallel()
	kc := controlConfig()
	kc.ControlClientSPKISHA256 = []string{"abcd"}
	_, err := kesAgentProfiles(kc)
	if err == nil || !strings.Contains(err.Error(), "must be 64 hex characters") {
		t.Fatalf("err = %v", err)
	}
}

func TestKESAgentProfilesSignListNeedsClientCertVerification(t *testing.T) {
	t.Parallel()
	ok, err := kesAgentProfiles(signConfig())
	if err != nil {
		t.Fatalf("sign list with a client CA: %v", err)
	}
	if len(ok) != 1 || len(ok[0].SignClientSPKI) != 1 {
		t.Fatalf("sign list not carried to the profile: %+v", ok)
	}

	kc := signConfig()
	kc.AttestedClientCAFile = ""
	if _, err := kesAgentProfiles(kc); err == nil ||
		!strings.Contains(err.Error(), "sign_client_spki_sha256") {
		t.Fatalf("err = %v, want a sign_client_spki_sha256 refusal", err)
	}

	kc = signConfig()
	kc.SignClientSPKISHA256 = []string{"abcd"}
	if _, err := kesAgentProfiles(kc); err == nil ||
		!strings.Contains(err.Error(), "must be 64 hex characters") {
		t.Fatalf("malformed signing SPKI: %v", err)
	}
}

func TestKESAgentProfilesRefusesTopLevelControlListWithProfiles(t *testing.T) {
	t.Parallel()
	kc := controlConfig()
	kc.ColdVKeyHex, kc.SystemStart, kc.SlotsPerKESPeriod, kc.GuardFile = "", "", 0, ""
	kc.Profiles = []config.KESAgentProfileConfig{{
		Name:              "pool",
		ColdVKeyHex:       testColdVKeyHex,
		SystemStart:       "2022-10-25T00:00:00Z",
		SlotsPerKESPeriod: 129600,
		GuardFile:         "/var/lib/bursa/guard.json",
	}}
	_, err := kesAgentProfiles(kc)
	if err == nil || !strings.Contains(err.Error(), "control_client_spki_sha256 and sign_client_spki_sha256; set them in each profile") {
		t.Fatalf("err = %v", err)
	}
}

func TestKESAgentProfileCarriesNetworkMagic(t *testing.T) {
	t.Parallel()
	pc := config.KESAgentProfileConfig{
		Name:              "net",
		ColdVKeyHex:       testColdVKeyHex,
		SystemStart:       "2026-10-18T00:00:00Z",
		NetworkMagic:      42,
		SlotLength:        1,
		SlotsPerKESPeriod: 129600,
		GuardFile:         "/var/lib/bursa/net.json",
	}
	got, err := kesAgentProfile(pc, "kes_agent.profiles[0]")
	if err != nil {
		t.Fatalf("kesAgentProfile: %v", err)
	}
	if got.NetworkMagic != 42 {
		t.Fatalf("NetworkMagic = %d, want 42", got.NetworkMagic)
	}
}
