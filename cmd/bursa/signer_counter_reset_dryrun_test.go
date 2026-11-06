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
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/jackc/pgx/v5"
)

// dryRunReset runs the command without --yes and requires the not-confirmed
// result and a report of no records.
func dryRunReset(t *testing.T, cfg config.SignerWatermarkConfig, key string) {
	t.Helper()
	var out bytes.Buffer
	err := runSignerCounterReset(
		context.Background(), &out, cfg, key, 10, false,
	)
	if !errors.Is(err, errCounterResetNotConfirmed) {
		t.Fatalf("err = %v, want errCounterResetNotConfirmed", err)
	}
	if !strings.Contains(out.String(), "none") {
		t.Fatalf("output lacks the empty records:\n%s", out.String())
	}
}

// requireUnchangedFile fails when path differs from want or a WAL or journal
// file appeared beside it.
func requireUnchangedFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf(
			"dry run changed the store: %d bytes, was %d",
			len(got),
			len(want),
		)
	}
	for _, suffix := range []string{"-wal", "-journal"} {
		if _, err := os.Stat(path + suffix); err == nil {
			t.Fatalf("dry run created %s", filepath.Base(path+suffix))
		}
	}
}

func TestSignerCounterReset_DryRunLeavesEmptySqliteFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wm.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dryRunReset(
		t,
		config.SignerWatermarkConfig{Type: "file", Path: path},
		resetKeyHex,
	)
	requireUnchangedFile(t, path, nil)
}

func TestSignerCounterReset_DryRunLeavesPartialSqliteSchema(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wm.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`CREATE TABLE watermark (record_key TEXT PRIMARY KEY)`,
	); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dryRunReset(
		t,
		config.SignerWatermarkConfig{Type: "file", Path: path},
		resetKeyHex,
	)
	requireUnchangedFile(t, path, want)
}

// TestSignerCounterReset_DryRunPostgresFreshSchema runs a dry run against an
// empty schema and requires that no table was created in it.
func TestSignerCounterReset_DryRunPostgresFreshSchema(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("BURSA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip(
			"BURSA_TEST_POSTGRES_DSN not set; skipping Postgres runtime tests",
		)
	}
	ctx := context.Background()
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	schema := "reset_dry_" + hex.EncodeToString(raw[:])
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(
			context.Background(), "DROP SCHEMA "+schema+" CASCADE",
		)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	var key [28]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	dryRunReset(
		t,
		config.SignerWatermarkConfig{Type: "postgres", DSN: u.String()},
		hex.EncodeToString(key[:]),
	)
	var tables int
	if err := admin.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema = $1`,
		schema).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatalf("dry run created %d tables in a fresh schema", tables)
	}
}
