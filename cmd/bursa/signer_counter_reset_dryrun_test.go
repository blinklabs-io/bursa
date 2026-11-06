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
	"regexp"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa/internal/config"
	"github.com/jackc/pgx/v5"
)

// dryRunReset runs the command without --yes, requires the not-confirmed
// result, and returns the output.
func dryRunReset(
	t *testing.T,
	cfg config.SignerWatermarkConfig,
	key string,
) string {
	t.Helper()
	var out bytes.Buffer
	err := runSignerCounterReset(
		context.Background(), &out, cfg, key, "", 10, false,
	)
	if !errors.Is(err, errCounterResetNotConfirmed) {
		t.Fatalf("err = %v, want errCounterResetNotConfirmed", err)
	}
	return out.String()
}

// requireBefore fails unless the before section of out reports each of the
// three records with the given value, "none" for no record.
func requireBefore(t *testing.T, out, floor, issued, explicit string) {
	t.Helper()
	start := strings.Index(out, "before:\n")
	end := strings.Index(out, "would become:")
	if start < 0 || end < start {
		t.Fatalf("output lacks the before section:\n%s", out)
	}
	section := out[start:end]
	for _, rec := range []struct{ name, want string }{
		{"opcert-chain-floor", floor},
		{"opcert-chain-issued", issued},
		{"opcert-counter (unchanged)", explicit},
	} {
		re := regexp.MustCompile(
			`(?m)^\s+` + regexp.QuoteMeta(rec.name) + `\s+(\S+)$`,
		)
		m := re.FindStringSubmatch(section)
		if m == nil || m[1] != rec.want {
			t.Fatalf(
				"before %s = %v, want %s:\n%s",
				rec.name,
				m,
				rec.want,
				out,
			)
		}
	}
}

// withSearchPath returns dsn with search_path set to schema, in either the
// URL or the keyword/value DSN form.
func withSearchPath(dsn, schema string) (string, error) {
	if !strings.Contains(dsn, "://") {
		return strings.TrimSpace(dsn) + " search_path=" + schema, nil
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func TestWithSearchPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ dsn, want string }{
		{
			"postgres://u:p@127.0.0.1:5432/db?sslmode=disable",
			"postgres://u:p@127.0.0.1:5432/db?search_path=s1&sslmode=disable",
		},
		{
			"host=127.0.0.1 port=5432 dbname=db sslmode=disable",
			"host=127.0.0.1 port=5432 dbname=db sslmode=disable search_path=s1",
		},
	} {
		got, err := withSearchPath(tc.dsn, "s1")
		if err != nil || got != tc.want {
			t.Errorf(
				"withSearchPath(%q) = %q, %v; want %q",
				tc.dsn,
				got,
				err,
				tc.want,
			)
		}
		cfg, err := pgx.ParseConfig(got)
		if err != nil || cfg.RuntimeParams["search_path"] != "s1" {
			t.Errorf("%q: search_path not parsed: %v", got, err)
		}
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
	out := dryRunReset(
		t,
		config.SignerWatermarkConfig{Type: "file", Path: path},
		resetKeyHex,
	)
	requireBefore(t, out, "none", "none", "none")
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
	out := dryRunReset(
		t,
		config.SignerWatermarkConfig{Type: "file", Path: path},
		resetKeyHex,
	)
	requireBefore(t, out, "none", "none", "none")
	requireUnchangedFile(t, path, want)
}

// TestSignerCounterReset_DryRunRelativePath reads, through a relative store
// path, the records an applying reset would change. Not parallel: it changes
// the working directory.
func TestSignerCounterReset_DryRunRelativePath(t *testing.T) {
	cfg, _ := seedResetStore(t)
	dir, name := filepath.Split(filepath.Clean(cfg.Path))
	parent, sub := filepath.Split(filepath.Clean(dir))
	t.Chdir(parent)
	cfg.Path = filepath.Join(sub, name)
	out := dryRunReset(t, cfg, resetKeyHex)
	requireBefore(t, out, "8", "9", "9")
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
	schemaDSN, err := withSearchPath(dsn, schema)
	if err != nil {
		t.Fatal(err)
	}

	var key [28]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	out := dryRunReset(
		t,
		config.SignerWatermarkConfig{Type: "postgres", DSN: schemaDSN},
		hex.EncodeToString(key[:]),
	)
	requireBefore(t, out, "none", "none", "none")
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
