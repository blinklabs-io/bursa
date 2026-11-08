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

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The transport and auth options default to off, so an existing config keeps
// its behaviour, and each one is read from YAML and from its env variable.
func TestSignerTransportOptions(t *testing.T) {
	cfg, err := LoadConfigFile("")
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if cfg.Signer.AuthNone || cfg.Signer.Plaintext ||
		cfg.Signer.JWKSPlaintext {
		t.Fatalf("options default on: %+v", cfg.Signer)
	}

	path := filepath.Join(t.TempDir(), "bursa.yaml")
	yaml := `
signer:
  auth_none: true
  plaintext: true
  jwks_plaintext: true
  backends:
    - name: v
      type: vault
      plaintext: true
    - name: cs
      type: confidential-space
      plaintext: true
      jwks_plaintext: true
    - name: armory
      type: armory
      tls_ca_file: /ca.pem
      tls_client_cert_file: /client.pem
      tls_client_key_file: /client.key
    - name: off
      type: vault
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	s := cfg.Signer
	if !s.AuthNone || !s.Plaintext || !s.JWKSPlaintext {
		t.Fatalf("signer options not read from YAML: %+v", s)
	}
	if len(s.Backends) != 4 {
		t.Fatalf("backends = %d, want 4", len(s.Backends))
	}
	if !s.Backends[0].Plaintext {
		t.Error("vault plaintext not read")
	}
	if !s.Backends[1].Plaintext || !s.Backends[1].JWKSPlaintext {
		t.Error("confidential-space plaintext options not read")
	}
	if a := s.Backends[2]; a.TLSCAFile != "/ca.pem" ||
		a.TLSClientCertFile != "/client.pem" ||
		a.TLSClientKeyFile != "/client.key" {
		t.Errorf("armory TLS files not read: %+v", a)
	}
	if s.Backends[3].Plaintext || s.Backends[3].JWKSPlaintext {
		t.Error("unset backend options default on")
	}

	for env, field := range map[string]func(SignerConfig) bool{
		"SIGNER_AUTH_NONE":      func(c SignerConfig) bool { return c.AuthNone },
		"SIGNER_PLAINTEXT":      func(c SignerConfig) bool { return c.Plaintext },
		"SIGNER_JWKS_PLAINTEXT": func(c SignerConfig) bool { return c.JWKSPlaintext },
	} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "true")
			cfg, err := LoadConfigFile("")
			if err != nil {
				t.Fatalf("LoadConfigFile: %v", err)
			}
			if !field(cfg.Signer) {
				t.Fatalf("%s=true not applied", env)
			}
		})
	}
}
