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
	"context"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

func TestBuildWatermark_MemDefault(t *testing.T) {
	wm, mode, err := BuildWatermark(context.Background(), config.SignerWatermarkConfig{})
	if err != nil {
		t.Fatalf("BuildWatermark: %v", err)
	}
	if _, ok := wm.(*watermark.MemWatermark); !ok {
		t.Fatalf("default type: got %T, want *MemWatermark", wm)
	}
	if mode != watermark.ModeEnforce {
		t.Fatalf("default mode: got %q, want enforce", mode)
	}
}

func TestBuildWatermark_FileRequiresPath(t *testing.T) {
	_, _, err := BuildWatermark(context.Background(), config.SignerWatermarkConfig{Type: "file"})
	if err == nil || !strings.Contains(err.Error(), "non-empty path") {
		t.Fatalf("file without path: want non-empty-path error, got %v", err)
	}
}

func TestBuildWatermark_UnknownType(t *testing.T) {
	_, _, err := BuildWatermark(context.Background(), config.SignerWatermarkConfig{Type: "bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown watermark type") {
		t.Fatalf("unknown type: want unknown-type error, got %v", err)
	}
}

func TestBuildWatermark_PostgresRequiresDSN(t *testing.T) {
	_, _, err := BuildWatermark(context.Background(), config.SignerWatermarkConfig{Type: "postgres"})
	if err == nil || !strings.Contains(err.Error(), "requires dsn or dsn_env") {
		t.Fatalf("postgres without dsn: want dsn-required error, got %v", err)
	}
}

func TestWatermarkPostgresDSN_DSNEnvPrecedence(t *testing.T) {
	t.Setenv("BURSA_TEST_WM_DSN", "postgres://from-env/db")
	dsn, err := watermarkPostgresDSN(config.SignerWatermarkConfig{
		Type:   "postgres",
		DSN:    "postgres://from-plaintext/db",
		DSNEnv: "BURSA_TEST_WM_DSN",
	})
	if err != nil {
		t.Fatalf("watermarkPostgresDSN: %v", err)
	}
	if dsn != "postgres://from-env/db" {
		t.Fatalf("dsn_env must win over plaintext dsn: got %q", dsn)
	}
}

func TestWatermarkPostgresDSN_DSNEnvEmpty(t *testing.T) {
	// dsn_env set but the variable is unset/empty is a configuration error, not
	// a silent fallback to a plaintext dsn.
	_, err := watermarkPostgresDSN(config.SignerWatermarkConfig{
		Type:   "postgres",
		DSN:    "postgres://from-plaintext/db",
		DSNEnv: "BURSA_TEST_WM_DSN_UNSET",
	})
	if err == nil || !strings.Contains(err.Error(), "is set but the environment variable is empty") {
		t.Fatalf("empty dsn_env var: want empty-env error, got %v", err)
	}
}

func TestWatermarkPostgresDSN_PlaintextFallback(t *testing.T) {
	dsn, err := watermarkPostgresDSN(config.SignerWatermarkConfig{
		Type: "postgres",
		DSN:  "postgres://plaintext/db",
	})
	if err != nil {
		t.Fatalf("watermarkPostgresDSN: %v", err)
	}
	if dsn != "postgres://plaintext/db" {
		t.Fatalf("plaintext dsn fallback: got %q", dsn)
	}
}
