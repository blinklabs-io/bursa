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
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
)

// The following tests exercise buildPKCS11Backend's config validation, which is
// pure Go and runs in both build configurations (it fails before reaching the
// tag-gated driver). See internal/signer/backend/pkcs11_softhsm_test.go for the
// -tags pkcs11 runtime test against SoftHSM.

func TestBuildPKCS11Backend_RequiresModule(t *testing.T) {
	_, err := buildPKCS11Backend(config.SignerBackendConfig{
		Name: "hsm", Type: "pkcs11", TokenLabel: "bursa", PINEnv: "PKCS11_PIN",
	})
	if err == nil || !strings.Contains(err.Error(), "module") {
		t.Fatalf("expected module error, got %v", err)
	}
}

func TestBuildPKCS11Backend_RequiresTokenOrSlot(t *testing.T) {
	_, err := buildPKCS11Backend(config.SignerBackendConfig{
		Name: "hsm", Type: "pkcs11", Module: "/lib/softhsm.so", PINEnv: "PKCS11_PIN",
	})
	if err == nil || !strings.Contains(err.Error(), "token_label or slot") {
		t.Fatalf("expected token_label/slot error, got %v", err)
	}
}

func TestBuildPKCS11Backend_RequiresPinEnv(t *testing.T) {
	_, err := buildPKCS11Backend(config.SignerBackendConfig{
		Name: "hsm", Type: "pkcs11", Module: "/lib/softhsm.so", TokenLabel: "bursa",
	})
	if err == nil || !strings.Contains(err.Error(), "pin_env") {
		t.Fatalf("expected pin_env error, got %v", err)
	}
}

func TestBuildPKCS11Backend_EmptyPin(t *testing.T) {
	t.Setenv("PKCS11_PIN", "")
	_, err := buildPKCS11Backend(config.SignerBackendConfig{
		Name: "hsm", Type: "pkcs11", Module: "/lib/softhsm.so",
		TokenLabel: "bursa", PINEnv: "PKCS11_PIN",
	})
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected empty PIN error, got %v", err)
	}
}

func TestBuildPKCS11Backend_InvalidKeyType(t *testing.T) {
	t.Setenv("PKCS11_PIN", "1234")
	_, err := buildPKCS11Backend(config.SignerBackendConfig{
		Name: "hsm", Type: "pkcs11", Module: "/lib/softhsm.so",
		TokenLabel: "bursa", PINEnv: "PKCS11_PIN",
		Keys: []config.SignerBackendKeyConfig{{Name: "k", Type: "bogus"}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid key type") {
		t.Fatalf("expected invalid key type error, got %v", err)
	}
}
