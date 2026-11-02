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

package watermark

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const insecureRemoteTargetMsg = "requires hostname-verified TLS"

func TestValidatePostgresWatermarkConfigAllowsLocalOrVerifiedTargets(t *testing.T) {
	tests := map[string]string{
		"unix socket":              "host=/var/run/postgresql dbname=wm sslmode=disable",
		"localhost plaintext":      "postgres://u@localhost/wm?sslmode=disable",
		"localhost mixed case":     "postgres://u@LocalHost/wm?sslmode=disable",
		"ipv4 loopback plaintext":  "postgres://u@127.0.0.1/wm?sslmode=disable",
		"ipv4 loopback range":      "postgres://u@127.0.0.2/wm?sslmode=disable",
		"ipv6 loopback plaintext":  "postgres://u@[::1]/wm?sslmode=disable",
		"loopback default sslmode": "postgres://u@127.0.0.1/wm",
		"remote verify-full":       "postgres://u@db.example.com/wm?sslmode=verify-full",
		"remote ip verify-full":    "postgres://u@192.0.2.10/wm?sslmode=verify-full",
		"remote system root":       "postgres://u@db.example.com/wm?sslrootcert=system",
		"local and verified remote": "host=localhost,db.example.com dbname=wm " +
			"sslmode=verify-full",
	}
	for name, dsn := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatalf("ParseConfig(%q): %v", dsn, err)
			}
			if err := validatePostgresWatermarkConfig(cfg.ConnConfig); err != nil {
				t.Fatalf("validatePostgresWatermarkConfig(%q) = %v, want nil", dsn, err)
			}
		})
	}
}

func TestValidatePostgresWatermarkConfigRejectsUnverifiedRemoteTargets(t *testing.T) {
	tests := map[string]string{
		"default sslmode (prefer)": "postgres://u@db.example.com/wm",
		"disable":                  "postgres://u@db.example.com/wm?sslmode=disable",
		"allow":                    "postgres://u@db.example.com/wm?sslmode=allow",
		"prefer":                   "postgres://u@db.example.com/wm?sslmode=prefer",
		"require":                  "postgres://u@db.example.com/wm?sslmode=require",
		"verify-ca":                "postgres://u@db.example.com/wm?sslmode=verify-ca",
		"remote ip require":        "postgres://u@192.0.2.10/wm?sslmode=require",
		"localhost-like name":      "postgres://u@localhost.example.com/wm?sslmode=disable",
		"unspecified address":      "postgres://u@0.0.0.0/wm?sslmode=disable",
		"plaintext remote fallback": "host=localhost,db.example.com dbname=wm " +
			"sslmode=disable",
	}
	for name, dsn := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatalf("ParseConfig(%q): %v", dsn, err)
			}
			err = validatePostgresWatermarkConfig(cfg.ConnConfig)
			if err == nil || !strings.Contains(err.Error(), insecureRemoteTargetMsg) {
				t.Fatalf(
					"validatePostgresWatermarkConfig(%q) = %v, want %q error",
					dsn, err, insecureRemoteTargetMsg,
				)
			}
		})
	}
}

func TestNewPostgresWatermarkRejectsUnverifiedRemoteBeforeConnecting(t *testing.T) {
	// The .invalid TLD never resolves, so a connection attempt would surface a
	// lookup error instead of the TLS policy error asserted here.
	dsn := "postgres://u@db.example.invalid/wm?sslmode=require&connect_timeout=1"
	wm, err := NewPostgresWatermark(context.Background(), dsn)
	if wm != nil {
		wm.Close()
	}
	if err == nil || !strings.Contains(err.Error(), insecureRemoteTargetMsg) {
		t.Fatalf("NewPostgresWatermark(%q) = %v, want %q error", dsn, err, insecureRemoteTargetMsg)
	}
}
