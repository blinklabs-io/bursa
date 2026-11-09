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

package device

import (
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
)

// modeLog collects the lines a service logs.
type modeLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *modeLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *modeLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.lines = nil
}

func (l *modeLog) has(line string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Contains(l.lines, line)
}

// HostAuthMode is hostAuthMode under the service lock.
func (s *Service) HostAuthMode() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.hostAuthMode()
}

// modeService returns a service of the given image on chip, logging to l.
// chain is empty for a testnet image and "multi" for a multi image.
func modeService(
	t *testing.T,
	chip *fakeChip,
	chain string,
	provisioning bool,
	l *modeLog,
) *Service {
	t.Helper()

	s := New(&sync.Mutex{}, l.logf)

	switch chain {
	case "":
		s.SetNetwork(0, "")
	case "multi":
		s.SetScopes(MultiScopes())
	default:
		s.SetNetwork(1, chain)
	}

	if provisioning {
		s.AllowFirstHostKey()
	}

	if err := s.SetChip(chip); err != nil {
		t.Fatal(err)
	}

	return s
}

// TestHostAuthModeReported checks the mode each image reports when the chip
// is set, and that the report matches whether the image takes an unsigned
// host key.
func TestHostAuthModeReported(t *testing.T) {
	// a chip holding one testnet host key
	testnetKeyed := func(t *testing.T) *fakeChip {
		chip := newFakeChip()
		registerHostKey(
			t,
			modeService(t, chip, "", false, &modeLog{}),
			hostPub(testHostKey),
		)

		return chip
	}

	cases := []struct {
		name         string
		chip         func(*testing.T) *fakeChip
		chain        string
		provisioning bool
		want         string
		unsignedOK   bool
	}{
		{
			name: "testnet bootstrap", chip: func(*testing.T) *fakeChip { return newFakeChip() },
			want: hostAuthBootstrap, unsignedOK: true,
		},
		{
			name: "testnet with a host key", chip: testnetKeyed,
			want: hostAuthRequired,
		},
		{
			name: "mainnet bootstrap", chip: func(*testing.T) *fakeChip { return newFakeChip() },
			chain: "cardano-mainnet", want: hostAuthBootstrapAdmin, unsignedOK: true,
		},
		{
			name: "mainnet with another scope's key", chip: testnetKeyed,
			chain: "cardano-mainnet", want: hostAuthRequired,
		},
		{
			name: "multi signing image", chip: func(*testing.T) *fakeChip { return newFakeChip() },
			chain: "multi", want: hostAuthRequired,
		},
		{
			name: "multi provisioning image", chip: func(*testing.T) *fakeChip { return newFakeChip() },
			chain: "multi", provisioning: true, want: hostAuthFirstKey, unsignedOK: true,
		},
		{
			name: "multi provisioning image with a host key", chip: testnetKeyed,
			chain: "multi", provisioning: true, want: hostAuthRequired,
		},
		{
			name: "unreadable host key list",
			chip: func(*testing.T) *fakeChip {
				chip := newFakeChip()
				chip.bins[hostKeysID] = []byte("torn")

				return chip
			},
			want: hostAuthBadList,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := &modeLog{}
			s := modeService(t, c.chip(t), c.chain, c.provisioning, l)

			if got := s.HostAuthMode(); got != c.want {
				t.Fatalf("HostAuthMode() = %q, want %q", got, c.want)
			}

			if !l.has(c.want) {
				t.Fatalf("SetChip did not log %q: %q", c.want, l.lines)
			}

			req := HostKeyRequest{PublicKey: hostPub(testHostKey2)}
			if c.chain == "multi" {
				req.Scope = scopeCardanoName
			}

			code, body := post(t, s, RouteProvisionHostKey, req)
			if (code == http.StatusOK) != c.unsignedOK {
				t.Fatalf(
					"unsigned host key add: %d %s, mode %q",
					code,
					body,
					c.want,
				)
			}
		})
	}
}

// TestHostAuthModeFollowsHostKeys checks the mode is reported again when the
// first host key is added and when a device wipe removes it.
func TestHostAuthModeFollowsHostKeys(t *testing.T) {
	l := &modeLog{}
	s := modeService(t, newFakeChip(), "", false, l)

	if got := s.HostAuthMode(); got != hostAuthBootstrap {
		t.Fatalf("new device: %q", got)
	}

	l.reset()
	registerHostKey(t, s, hostPub(testHostKey))

	if !l.has(hostAuthRequired) || s.HostAuthMode() != hostAuthRequired {
		t.Fatalf("after the first host key: %q, logged %q", s.HostAuthMode(), l.lines)
	}

	l.reset()

	// no identity key is provisioned, so the empty key confirms the wipe
	if code, body := rawPost(s.WipeHandler(), "/wipe/device", []byte(`{"identity_public_key":""}`)); code != http.StatusOK {
		t.Fatalf("wipe device: %d %s", code, body)
	}

	if !l.has(hostAuthBootstrap) || s.HostAuthMode() != hostAuthBootstrap {
		t.Fatalf("after a device wipe: %q, logged %q", s.HostAuthMode(), l.lines)
	}
}

// TestHostAuthModeAfterAllowFirstHostKey checks a provisioning image that
// allows the first host key after the chip is set reports the new mode.
func TestHostAuthModeAfterAllowFirstHostKey(t *testing.T) {
	l := &modeLog{}
	s := modeService(t, newFakeChip(), "multi", false, l)

	if !l.has(hostAuthRequired) {
		t.Fatalf("multi signing image did not log %q: %q", hostAuthRequired, l.lines)
	}

	s.AllowFirstHostKey()

	if !l.has(hostAuthFirstKey) || s.HostAuthMode() != hostAuthFirstKey {
		t.Fatalf("after AllowFirstHostKey: %q, logged %q", s.HostAuthMode(), l.lines)
	}
}
