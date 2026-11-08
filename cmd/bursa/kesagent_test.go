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
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/kesagent"
)

func TestParseSocketMode(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    os.FileMode
		wantErr bool
	}{
		{name: "empty defaults to 0600", in: "", want: 0o600},
		{name: "explicit 0600", in: "0600", want: 0o600},
		{name: "widened 0660", in: "0660", want: 0o660},
		{name: "whitespace trimmed", in: "  0600  ", want: 0o600},
		{name: "not octal", in: "not-a-mode", wantErr: true},
		{
			name:    "decimal 8/9 digits invalid in octal",
			in:      "0900",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSocketMode(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf(
						"parseSocketMode(%q): expected error, got mode %o",
						tt.in,
						got,
					)
				}
				return
			}
			if err != nil {
				t.Fatalf(
					"parseSocketMode(%q): unexpected error: %v",
					tt.in,
					err,
				)
			}
			if got != tt.want {
				t.Fatalf(
					"parseSocketMode(%q) = %o, want %o",
					tt.in,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestValidateControlSocketMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{name: "owner-only default", mode: 0o600},
		{name: "owner rwx only", mode: 0o700},
		{name: "group readable (not writable) is fine", mode: 0o640},
		{name: "group writable rejected", mode: 0o660, wantErr: true},
		{name: "other writable rejected", mode: 0o602, wantErr: true},
		{name: "group+other writable rejected", mode: 0o666, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateControlSocketMode(tt.mode)
			if tt.wantErr && err == nil {
				t.Fatalf(
					"validateControlSocketMode(%o): expected error, got nil",
					tt.mode,
				)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf(
					"validateControlSocketMode(%o): unexpected error: %v",
					tt.mode,
					err,
				)
			}
		})
	}
}

func TestValidateServiceSocketMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{name: "owner-only default", mode: 0o600},
		{name: "group readable is fine", mode: 0o640},
		{
			name: "group writable allowed (documented producer group)",
			mode: 0o660,
		},
		{name: "other readable is fine", mode: 0o604},
		{name: "other writable rejected", mode: 0o602, wantErr: true},
		{name: "world writable rejected", mode: 0o666, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServiceSocketMode(tt.mode)
			if tt.wantErr && err == nil {
				t.Fatalf(
					"validateServiceSocketMode(%o): expected error, got nil",
					tt.mode,
				)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf(
					"validateServiceSocketMode(%o): unexpected error: %v",
					tt.mode,
					err,
				)
			}
		})
	}
}

func TestLooksLikeText(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{
			name: "hex string",
			in: []byte(
				"0f0e0d0c0b0a09080706050403020100aabbccddeeff00112233445566778899",
			),
			want: true,
		},
		{
			name: "json envelope shape",
			in:   []byte(`{"type":"KesVerificationKey","cborHex":"5820"}`),
			want: true,
		},
		{name: "empty is text", in: []byte(""), want: true},
		{name: "contains a null byte", in: []byte("aaaa\x00aaaa"), want: false},
		{name: "high-bit random byte", in: []byte("aaaa\xffaaaa"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeText(tt.in); got != tt.want {
				t.Fatalf("looksLikeText(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestLoadColdVKeyRawBinaryFile guards the intended fast path: a genuine raw
// 32-byte binary verification key (not text-shaped) is returned as-is
// without being routed through the hex/JSON-envelope decoder.
func TestLoadColdVKeyRawBinaryFile(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	raw[0] = 0x00 // guarantee a non-printable byte regardless of the fill pattern
	path := filepath.Join(t.TempDir(), "cold.vkey")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write cold vkey: %v", err)
	}
	got, err := loadColdVKey("", path)
	if err != nil {
		t.Fatalf("loadColdVKey: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("loadColdVKey returned %d bytes, want 32", len(got))
	}
	for i, b := range got {
		if b != raw[i] {
			t.Fatalf("loadColdVKey byte %d = %x, want %x", i, b, raw[i])
		}
	}
}

// TestLoadColdVKeyMalformedTextFileOfLength32 guards the cubic P2 fix: a
// text-shaped 32-byte file that is not valid hex or a JSON envelope must
// produce a clear decode error, not be silently accepted as raw key bytes
// just because its length happens to be 32.
func TestLoadColdVKeyMalformedTextFileOfLength32(t *testing.T) {
	// Exactly 32 printable ASCII bytes, and not valid hex (contains 'z' and
	// spaces), so both the old raw-passthrough and the hex/CBOR decoder
	// would previously disagree about how to interpret it; it must now
	// error out via the decode path rather than being accepted as raw bytes.
	malformed := []byte("not-a-valid-cold-vkey!!-zzzzzzzz")
	if len(malformed) != 32 {
		t.Fatalf(
			"test fixture must be exactly 32 bytes, got %d",
			len(malformed),
		)
	}
	path := filepath.Join(t.TempDir(), "cold.vkey")
	if err := os.WriteFile(path, malformed, 0o600); err != nil {
		t.Fatalf("write cold vkey: %v", err)
	}
	if _, err := loadColdVKey("", path); err == nil {
		t.Fatal(
			"expected loadColdVKey to reject malformed text-shaped 32-byte input",
		)
	}
}

func TestAttestedServiceConfigIdentityKey(t *testing.T) {
	t.Parallel()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	keyFile := filepath.Join(t.TempDir(), "identity.skey")
	envelope := `{"type":"` + kesagent.IdentityKeyFileType +
		`","cborHex":"5820` + hex.EncodeToString(seed) + `"}`
	if err := os.WriteFile(keyFile, []byte(envelope), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := attestedServiceConfig(config.KESAgentConfig{
		AttestationProvider:        kesagent.IdentityKeyProvider,
		AttestationIdentityKeyFile: keyFile,
	})
	if err != nil {
		t.Fatalf("identity-key without attester_address refused: %v", err)
	}
	if cfg.Provider != kesagent.IdentityKeyProvider || cfg.Attester == nil {
		t.Fatalf("config = %+v", cfg)
	}
	binding := kesagent.AttestationBinding(
		[]byte("n"), []byte("c"), []byte("k"), []byte("o"), 1,
	)
	ev, err := cfg.Attester.Evidence(t.Context(), binding)
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, binding, ev) {
		t.Fatal("evidence is not the identity key's signature over the binding")
	}

	if _, err := attestedServiceConfig(config.KESAgentConfig{
		AttestationProvider: kesagent.IdentityKeyProvider,
	}); err == nil {
		t.Fatal("identity-key without a key file accepted")
	}
	if _, err := attestedServiceConfig(config.KESAgentConfig{
		AttestationProvider:        kesagent.IdentityKeyProvider,
		AttestationIdentityKeyFile: filepath.Join(t.TempDir(), "missing"),
	}); err == nil {
		t.Fatal("identity-key with a missing key file accepted")
	}
}

func TestAttestedServiceConfigPlatformProvidersUnchanged(t *testing.T) {
	t.Parallel()
	if _, err := attestedServiceConfig(config.KESAgentConfig{}); err == nil {
		t.Fatal("no provider and no attester accepted")
	}
	if _, err := attestedServiceConfig(config.KESAgentConfig{
		AttesterAddress: "unix:///run/bursa/attester.sock",
	}); err == nil {
		t.Fatal("attester without a provider accepted")
	}
	for _, provider := range []string{"nitro", "confidential-space"} {
		if _, err := attestedServiceConfig(config.KESAgentConfig{
			AttestationProvider: provider,
		}); err == nil {
			t.Fatalf("%s without attester_address accepted", provider)
		}
		cfg, err := attestedServiceConfig(config.KESAgentConfig{
			AttestationProvider: provider,
			AttesterAddress:     "unix:///run/bursa/attester.sock",
		})
		if err != nil || cfg.Provider != provider {
			t.Fatalf("%s with attester refused: %v", provider, err)
		}
	}
}

func TestGenIdentityKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	skey := filepath.Join(dir, "identity.skey")
	vkey := filepath.Join(dir, "identity.vkey")
	var out bytes.Buffer
	if err := genIdentityKey(skey, vkey, &out); err != nil {
		t.Fatalf("genIdentityKey: %v", err)
	}

	key, err := kesagent.LoadIdentityKey(skey)
	if err != nil {
		t.Fatalf("generated key does not load: %v", err)
	}
	pub := key.Public().(ed25519.PublicKey)
	if got := strings.TrimSpace(out.String()); got != hex.EncodeToString(pub) {
		t.Fatalf("printed public key %q does not match the signing key", got)
	}
	if strings.Contains(out.String(), hex.EncodeToString(key.Seed())) {
		t.Fatal("stdout contains the private seed")
	}

	vdata, err := os.ReadFile(vkey)
	if err != nil {
		t.Fatalf("read vkey: %v", err)
	}
	var env struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(vdata, &env); err != nil {
		t.Fatalf("vkey is not JSON: %v", err)
	}
	if env.Type != kesagent.IdentityVKeyFileType ||
		env.CborHex != "5820"+hex.EncodeToString(pub) {
		t.Fatalf("vkey envelope = %+v", env)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(skey)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("signing key mode = %o, want 600", fi.Mode().Perm())
		}
	}

	before, _ := os.ReadFile(skey)
	if err := genIdentityKey(skey, filepath.Join(dir, "other.vkey"), &out); err == nil {
		t.Fatal("existing signing key file was overwritten")
	}
	if after, _ := os.ReadFile(skey); !bytes.Equal(before, after) {
		t.Fatal("existing signing key file content changed")
	}
	if err := genIdentityKey(filepath.Join(dir, "other.skey"), vkey, &out); err == nil {
		t.Fatal("existing verification key file was overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "other.skey")); err == nil {
		t.Fatal("signing key left behind after the verification key was refused")
	}
}
