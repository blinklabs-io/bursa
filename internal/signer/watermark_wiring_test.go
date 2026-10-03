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
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/blinklabs-io/bursa/internal/signer/watermark"
)

func TestBuildWatermark_MemRefusedUnderEnforce(t *testing.T) {
	t.Parallel()
	// The zero value and an explicit "mem" both mean in-memory state, which a
	// restart wipes, so neither may back an enforced watermark.
	for _, c := range []config.SignerWatermarkConfig{
		{},
		{Type: "mem"},
		{Type: "mem", Mode: "enforce"},
	} {
		wm, _, err := BuildWatermark(context.Background(), c)
		if err == nil {
			t.Fatalf("config %+v: expected error, got store %T", c, wm)
		}
		if !strings.Contains(err.Error(), "durable") {
			t.Fatalf("config %+v: error should name durable storage, got %v", c, err)
		}
	}
}

func TestBuildWatermark_MemAllowedWhenNotEnforcing(t *testing.T) {
	t.Parallel()
	for _, mode := range []watermark.Mode{watermark.ModeWarn, watermark.ModeOff} {
		wm, got, err := BuildWatermark(context.Background(), config.SignerWatermarkConfig{Mode: string(mode)})
		if err != nil {
			t.Fatalf("mode %q: BuildWatermark: %v", mode, err)
		}
		if _, ok := wm.(*watermark.MemWatermark); !ok {
			t.Fatalf("mode %q: got %T, want *MemWatermark", mode, wm)
		}
		if got != mode {
			t.Fatalf("mode: got %q, want %q", got, mode)
		}
	}
}

func TestBuildWatermark_EnforcedFileSurvivesRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg := config.SignerWatermarkConfig{
		Type: "file",
		Path: filepath.Join(t.TempDir(), "wm.db"),
		Mode: "enforce",
	}
	var key backend.KeyHash
	key[0] = 9

	first, mode, err := BuildWatermark(ctx, cfg)
	if err != nil {
		t.Fatalf("first BuildWatermark: %v", err)
	}
	if mode != watermark.ModeEnforce {
		t.Fatalf("mode: got %q, want enforce", mode)
	}
	if err := first.CheckAndCommit(ctx, key, "tx:restart", []byte("payload-1")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := first.(io.Closer).Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, _, err := BuildWatermark(ctx, cfg)
	if err != nil {
		t.Fatalf("second BuildWatermark: %v", err)
	}
	defer second.(io.Closer).Close()
	err = second.CheckAndCommit(ctx, key, "tx:restart", []byte("payload-2"))
	if !errors.Is(err, watermark.ErrConflict) {
		t.Fatalf("divergent payload after restart: got %v, want ErrConflict", err)
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
