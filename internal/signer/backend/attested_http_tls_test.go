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

package backend

import (
	"crypto/ed25519"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnclaveTLSConfig(t *testing.T) {
	t.Parallel()
	empty, err := LoadEnclaveTLSConfig(EnclaveTLSFiles{})
	if err != nil {
		t.Fatalf("no files: %v", err)
	}
	if empty.RootCAs != nil || len(empty.Certificates) != 0 ||
		empty.MinVersion != tls.VersionTLS12 {
		t.Fatalf("no files: got %+v, want system roots and TLS 1.2", empty)
	}
	v13, err := LoadEnclaveTLSConfig(
		EnclaveTLSFiles{MinVersion: tls.VersionTLS13},
	)
	if err != nil || v13.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion: got %v, %v", v13, err)
	}

	noCerts := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(noCerts, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		files EnclaveTLSFiles
		want  string
	}{
		{
			"client certificate without key",
			EnclaveTLSFiles{ClientCertFile: "/c.pem"},
			"set together",
		},
		{
			"client key without certificate",
			EnclaveTLSFiles{ClientKeyFile: "/k.pem"},
			"set together",
		},
		{
			"CA file without certificates",
			EnclaveTLSFiles{CAFile: noCerts},
			"no certificates",
		},
		{
			"missing CA file",
			EnclaveTLSFiles{CAFile: filepath.Join(t.TempDir(), "none")},
			"tls_ca_file",
		},
	} {
		if _, err := LoadEnclaveTLSConfig(tc.files); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf(
				"%s: got %v, want error containing %q",
				tc.name,
				err,
				tc.want,
			)
		}
	}
}

func TestNewConfiguredHTTPEnclave(t *testing.T) {
	t.Parallel()
	_, hostKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	for _, tc := range []struct {
		name    string
		address string
		tls     *tls.Config
		hostKey ed25519.PrivateKey
		ok      bool
	}{
		{"http", "http://127.0.0.1:1", nil, nil, true},
		{"http with host key", "http://127.0.0.1:1", nil, hostKey, true},
		{"unix", "unix:///run/e.sock", nil, nil, true},
		{"https without TLS settings", "https://127.0.0.1:1", nil, nil, true},
		{"https with TLS and host key", "https://127.0.0.1:1", tlsConfig, hostKey, true},
		{"TLS on http", "http://127.0.0.1:1", tlsConfig, nil, false},
		{"TLS on unix", "unix:///run/e.sock", tlsConfig, nil, false},
		{"short host key", "http://127.0.0.1:1", nil, hostKey[:8], false},
	} {
		e, err := NewConfiguredHTTPEnclave(tc.address, "p", tc.tls, tc.hostKey)
		if tc.ok != (err == nil) {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
			continue
		}
		if err == nil && (e.hostKey != nil) != (tc.hostKey != nil) {
			t.Errorf("%s: host key set = %v", tc.name, e.hostKey != nil)
		}
	}
}
