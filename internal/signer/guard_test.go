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

package signer

import (
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
)

func TestIsLoopbackListenAddress(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":      true,
		"127.0.0.1:8090": true,
		"localhost":      true,
		"localhost:8090": true,
		"::1":            true,
		"[::1]:8090":     true,
		"":               false,
		"0.0.0.0":        false,
		"0.0.0.0:8090":   false,
		"10.0.0.5":       false,
		"192.168.1.10":   false,
	}
	for addr, want := range cases {
		if got := IsLoopbackListenAddress(addr); got != want {
			t.Errorf("IsLoopbackListenAddress(%q) = %v, want %v", addr, got, want)
		}
	}
}

func softwareBackend() config.SignerBackendConfig {
	return config.SignerBackendConfig{Name: "local", Type: "software", Path: "/keys"}
}

func vaultBackend() config.SignerBackendConfig {
	return config.SignerBackendConfig{Name: "hsm", Type: "vault"}
}

func TestCheckFileBackendGuard_NonLoopbackNoOptIn_Errors(t *testing.T) {
	warn, err := CheckFileBackendGuard(
		[]config.SignerBackendConfig{softwareBackend()},
		"0.0.0.0",
		false,
	)
	if err == nil {
		t.Fatal("expected boot error for software backend on non-loopback address without opt-in")
	}
	if warn == "" {
		t.Error("expected a non-empty warning alongside the error")
	}
}

func TestCheckFileBackendGuard_NonLoopbackWithOptIn_Boots(t *testing.T) {
	warn, err := CheckFileBackendGuard(
		[]config.SignerBackendConfig{softwareBackend()},
		"0.0.0.0",
		true,
	)
	if err != nil {
		t.Fatalf("expected boot to proceed with opt-in, got error: %v", err)
	}
	if warn == "" {
		t.Error("expected a loud warning even with the opt-in set")
	}
}

func TestCheckFileBackendGuard_Loopback_BootsWithWarning(t *testing.T) {
	warn, err := CheckFileBackendGuard(
		[]config.SignerBackendConfig{softwareBackend()},
		"127.0.0.1",
		false,
	)
	if err != nil {
		t.Fatalf("expected loopback to boot without opt-in, got error: %v", err)
	}
	if warn == "" {
		t.Error("expected a loud warning even on loopback")
	}
}

func TestCheckFileBackendGuard_NoFileBackend_Silent(t *testing.T) {
	warn, err := CheckFileBackendGuard(
		[]config.SignerBackendConfig{vaultBackend()},
		"0.0.0.0",
		false,
	)
	if err != nil {
		t.Fatalf("vault-only backend must not trigger the guard, got: %v", err)
	}
	if warn != "" {
		t.Errorf("expected no warning for a vault-only backend, got %q", warn)
	}
}
