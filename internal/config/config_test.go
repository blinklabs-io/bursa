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

func TestSignerConfig_Env(t *testing.T) {
	// The envconfig tag is SIGNER_LISTEN_PORT; envconfig.Process("bursa",...)
	// reads the bare tag directly when a custom envconfig tag is set, so the
	// effective env var is SIGNER_LISTEN_PORT (not BURSA_SIGNER_LISTEN_PORT).
	t.Setenv("SIGNER_LISTEN_PORT", "19191")
	// Reset globalConfig to defaults so this test is independent.
	globalConfig = defaultConfig()
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Signer.ListenPort != 19191 {
		t.Fatalf("expected signer port 19191, got %d", cfg.Signer.ListenPort)
	}
}

func TestLoadConfigFile_SignerSection(t *testing.T) {
	yaml := `
signer:
  listen_address: "127.0.0.1"
  listen_port: 9090
  jwt_secret: "supersecret"
  tls_cert_file: "/tmp/cert.pem"
  tls_key_file: "/tmp/key.pem"
  watermark:
    type: "mem"
    mode: "warn"
  backends:
    - name: "primary"
      type: "software"
      path: "/tmp/keys"
  keys:
    - hash: "00000000000000000000000000000000000000000000000000000001"
      backend: "primary"
      allowed_requests: ["tx"]
      tx_policy:
        max_output_ada: 500
        allow_mint: false
`
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "bursa.yml")
	if err := os.WriteFile(cfgFile, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	// Reset globalConfig so prior test state doesn't bleed through.
	globalConfig = defaultConfig()
	cfg, err := LoadConfigFile(cfgFile)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}

	if cfg.Signer.ListenAddress != "127.0.0.1" {
		t.Errorf("listen_address: got %q, want 127.0.0.1", cfg.Signer.ListenAddress)
	}
	if cfg.Signer.ListenPort != 9090 {
		t.Errorf("listen_port: got %d, want 9090", cfg.Signer.ListenPort)
	}
	if cfg.Signer.JWTSecret != "supersecret" {
		t.Errorf("jwt_secret: got %q, want supersecret", cfg.Signer.JWTSecret)
	}
	if cfg.Signer.TLSCertFile != "/tmp/cert.pem" {
		t.Errorf("tls_cert_file: got %q, want /tmp/cert.pem", cfg.Signer.TLSCertFile)
	}
	if cfg.Signer.TLSKeyFile != "/tmp/key.pem" {
		t.Errorf("tls_key_file: got %q, want /tmp/key.pem", cfg.Signer.TLSKeyFile)
	}
	if len(cfg.Signer.Backends) != 1 || cfg.Signer.Backends[0].Name != "primary" {
		t.Errorf("backends not loaded: %+v", cfg.Signer.Backends)
	}
	if len(cfg.Signer.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(cfg.Signer.Keys))
	}
	k := cfg.Signer.Keys[0]
	if v, ok := k.TxPolicy["max_output_ada"]; !ok || v != 500 {
		t.Errorf("tx_policy.max_output_ada: got %v, want 500", v)
	}

	// Env override must beat file value.
	globalConfig = defaultConfig()
	t.Setenv("SIGNER_LISTEN_PORT", "7777")
	cfg2, err := LoadConfigFile(cfgFile)
	if err != nil {
		t.Fatalf("LoadConfigFile (env override): %v", err)
	}
	if cfg2.Signer.ListenPort != 7777 {
		t.Errorf("env override: got port %d, want 7777", cfg2.Signer.ListenPort)
	}
}

func TestLoadConfigFile_ResetsGlobalConfig(t *testing.T) {
	dir := t.TempDir()
	firstFile := filepath.Join(dir, "first.yml")
	if err := os.WriteFile(firstFile, []byte(`
signer:
  watermark:
    type: "file"
    path: "/tmp/watermark"
    mode: "warn"
  backends:
    - name: "primary"
      type: "software"
      path: "/tmp/keys"
  keys:
    - hash: "00000000000000000000000000000000000000000000000000000001"
      backend: "primary"
      allowed_requests: ["tx"]
`), 0o600); err != nil {
		t.Fatalf("write first config: %v", err)
	}
	secondFile := filepath.Join(dir, "second.yml")
	if err := os.WriteFile(secondFile, []byte(`
signer:
  listen_address: "127.0.0.1"
`), 0o600); err != nil {
		t.Fatalf("write second config: %v", err)
	}

	globalConfig = defaultConfig()
	if _, err := LoadConfigFile(firstFile); err != nil {
		t.Fatalf("LoadConfigFile first: %v", err)
	}
	cfg, err := LoadConfigFile(secondFile)
	if err != nil {
		t.Fatalf("LoadConfigFile second: %v", err)
	}

	if len(cfg.Signer.Backends) != 0 {
		t.Fatalf("backends persisted across loads: %+v", cfg.Signer.Backends)
	}
	if len(cfg.Signer.Keys) != 0 {
		t.Fatalf("keys persisted across loads: %+v", cfg.Signer.Keys)
	}
	if cfg.Signer.Watermark.Type != "mem" || cfg.Signer.Watermark.Mode != "enforce" || cfg.Signer.Watermark.Path != "" {
		t.Fatalf("watermark did not reset to defaults: %+v", cfg.Signer.Watermark)
	}
}

func TestLoadConfigFile_EmptyPath(t *testing.T) {
	globalConfig = defaultConfig()
	cfg, err := LoadConfigFile("")
	if err != nil {
		t.Fatalf("LoadConfigFile with empty path: %v", err)
	}
	// Default port should be preserved.
	if cfg.Signer.ListenPort != 8090 {
		t.Errorf("default port: got %d, want 8090", cfg.Signer.ListenPort)
	}
}
