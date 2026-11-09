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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

func TestResetProfile(t *testing.T) {
	t.Parallel()
	armory := func(profile string) config.SignerBackendConfig {
		return config.SignerBackendConfig{
			Name: "dev-" + profile, Type: "armory", Profile: profile,
		}
	}
	plain := []config.SignerBackendConfig{
		{Name: "soft", Type: "software"},
		{Name: "enclave", Type: "nitro"},
		// a profile field on a backend type that ignores it
		{Name: "vault", Type: "vault", Profile: "otg@preview"},
	}
	mixed := append(
		[]config.SignerBackendConfig{armory("otg@preview"), armory("otg@musashi")},
		plain...,
	)
	for _, tc := range []struct {
		name       string
		backends   []config.SignerBackendConfig
		profile    string
		unprofiled bool
		want       string
		wantErr    string
	}{
		{name: "no backends", want: ""},
		{name: "unprofiled config", backends: plain, want: ""},
		{
			name:     "unprofiled config, unprofiled flag",
			backends: plain, unprofiled: true, want: "",
		},
		{
			name:     "profile in an unprofiled config",
			backends: plain, profile: "otg@preview",
			wantErr: "no backend in the signer config has a profile",
		},
		{
			name:     "profiled config without a profile",
			backends: mixed,
			wantErr:  "pass --profile",
		},
		{
			name:     "profiled config, configured profile",
			backends: mixed, profile: "otg@musashi", want: "otg@musashi",
		},
		{
			name:     "sops profile",
			backends: []config.SignerBackendConfig{{Name: "s", Type: "sops", Profile: "pool-a"}},
			profile:  "pool-a", want: "pool-a",
		},
		{
			name:     "sops profiled config without a profile",
			backends: []config.SignerBackendConfig{{Name: "s", Type: "sops", Profile: "pool-a"}},
			wantErr:  "pass --profile",
		},
		{
			name:     "nitro profile",
			backends: []config.SignerBackendConfig{{Name: "n", Type: "nitro", Profile: "pool-a"}},
			profile:  "pool-a", want: "pool-a",
		},
		{
			name:     "profiled config, unknown profile",
			backends: mixed, profile: "otg@preprod",
			wantErr: `"otg@preprod" is not the profile of any backend`,
		},
		{
			name:     "profiled config, unprofiled flag",
			backends: mixed, unprofiled: true, want: "",
		},
		{
			name:     "both flags",
			backends: mixed, profile: "otg@preview", unprofiled: true,
			wantErr: "mutually exclusive",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resetProfile(tc.backends, tc.profile, tc.unprofiled)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got (%q, %v), want %q", got, err, tc.want)
			}
		})
	}
}

// A profiled reset changes the records under the profile and the issued
// record written without one, and prints both, in a dry run and when applied.
func TestSignerCounterReset_Profile(t *testing.T) {
	t.Parallel()
	cfg, wm := seedResetStore(t)
	ctx := context.Background()
	k, _ := backend.ParseKeyHash(resetKeyHex)
	const profile = "otg@preview"
	for scope, v := range map[string]uint64{
		"opcert-chain-floor|" + profile:  6,
		"opcert-chain-issued|" + profile: 7,
	} {
		if err := wm.CheckAndRaiseFloor(ctx, k, scope, v); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	err := runSignerCounterReset(ctx, &out, cfg, resetKeyHex, profile, 10, false)
	if !errors.Is(err, errCounterResetNotConfirmed) {
		t.Fatalf("dry run err = %v", err)
	}
	for _, want := range []string{
		"profile " + profile,
		"opcert-chain-issued (no profile)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("dry run output lacks %q:\n%s", want, out.String())
		}
	}
	requireBefore(t, out.String(), "6", "7", "none")

	out.Reset()
	if err := runSignerCounterReset(ctx, &out, cfg, resetKeyHex, profile, 10, true); err != nil {
		t.Fatalf("reset: %v", err)
	}
	r, err := signer.ReadOpCertRecords(ctx, wm, k, profile)
	if err != nil {
		t.Fatal(err)
	}
	if r.ChainFloor == nil || *r.ChainFloor != 10 || r.ChainIssued != nil ||
		r.LegacyChainIssued != nil {
		t.Fatalf("profiled records after reset: %+v", r)
	}
	// the floor written without a profile is not the profile's to change
	if u := resetRecords(t, wm, resetKeyHex); u.ChainFloor == nil ||
		*u.ChainFloor != 8 || *u.Explicit != 9 {
		t.Fatalf("unprofiled records after a profiled reset: %+v", u)
	}
	if o := resetRecords(t, wm, resetOtherHex); *o.ChainIssued != 9 {
		t.Fatalf("other key changed: %+v", o)
	}
}
