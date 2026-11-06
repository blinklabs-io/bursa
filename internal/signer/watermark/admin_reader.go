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
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// CounterReader reads counter records without writing. A missing counter
// table reads as no record.
type CounterReader interface {
	CounterFor(
		ctx context.Context,
		key backend.KeyHash,
		scope string,
	) (uint64, bool, error)
}

var (
	_ CounterReader = (*SqliteCounterReader)(nil)
	_ CounterReader = (*PostgresCounterReader)(nil)
)

// SqliteCounterReader reads a SQLite watermark store opened read-only. It
// creates no table and runs no migration; for a WAL store SQLite may create
// its own -wal and -shm files, which hold no records.
type SqliteCounterReader struct {
	db *sql.DB
}

// OpenSqliteCounterReader opens the SQLite store at path read-only. The file
// must exist.
func OpenSqliteCounterReader(path string) (*SqliteCounterReader, error) {
	uri, err := sqliteReadOnlyURI(path)
	if err != nil {
		return nil, fmt.Errorf("open watermark db read-only: %w", err)
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open watermark db read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf(
			"open watermark db read-only: %w",
			readOnlyDirHint(err),
		)
	}
	return &SqliteCounterReader{db: db}, nil
}

// readOnlyDirHint explains a SQLITE_READONLY failure of a read-only open. To
// read a WAL database SQLite creates its -shm file beside the store, which
// fails when the directory is not writable.
func readOnlyDirHint(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_READONLY {
		return fmt.Errorf(
			"%w (SQLite could not create its -wal or -shm file in the store's directory; run as a user that can write that directory)",
			err,
		)
	}
	return err
}

// sqliteReadOnlyURI returns a read-only SQLite URI for path. A relative path
// is made absolute, since a URI reads its first segment as an authority, and
// the path is escaped so spaces, '?' and '#' stay part of the file name.
func sqliteReadOnlyURI(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		// A Windows drive path: file:///C:/dir/wm.db.
		p = "/" + p
	}
	u := url.URL{
		Scheme:   "file",
		Path:     p,
		RawQuery: "mode=ro&_pragma=busy_timeout(5000)",
	}
	return u.String(), nil
}

// Close closes the underlying database.
func (r *SqliteCounterReader) Close() error { return r.db.Close() }

func (r *SqliteCounterReader) CounterFor(
	ctx context.Context,
	key backend.KeyHash,
	scope string,
) (uint64, bool, error) {
	var tables int
	if err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'counter_watermark'`,
	).Scan(&tables); err != nil {
		return 0, false, fmt.Errorf("counter watermark lookup: %w", err)
	}
	if tables == 0 {
		return 0, false, nil
	}
	var have string
	err := r.db.QueryRowContext(ctx,
		`SELECT counter FROM counter_watermark WHERE record_key = ?`,
		recordKey(key, scope)).Scan(&have)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("counter watermark lookup: %w", err)
	}
	return decodeStoredCounter(have)
}

// PostgresCounterReader reads a Postgres watermark store in READ ONLY
// transactions. It creates no table and runs no migration.
type PostgresCounterReader struct {
	pool *pgxpool.Pool
}

// OpenPostgresCounterReader connects to the store at dsn under the same
// connection rules as NewPostgresWatermark, without initializing the schema.
func OpenPostgresCounterReader(
	ctx context.Context,
	dsn string,
) (*PostgresCounterReader, error) {
	if dsn == "" {
		return nil, errors.New("postgres watermark: empty dsn")
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres watermark dsn: %w", err)
	}
	if err := validatePostgresWatermarkConfig(poolConfig.ConnConfig); err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open postgres watermark pool: %w", err)
	}
	return &PostgresCounterReader{pool: pool}, nil
}

// Close closes the connection pool.
func (r *PostgresCounterReader) Close() { r.pool.Close() }

func (r *PostgresCounterReader) CounterFor(
	ctx context.Context,
	key backend.KeyHash,
	scope string,
) (uint64, bool, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, false, fmt.Errorf("counter watermark lookup: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT to_regclass('signer_counter_watermark') IS NOT NULL`,
	).Scan(&exists); err != nil {
		return 0, false, fmt.Errorf("counter watermark lookup: %w", err)
	}
	if !exists {
		return 0, false, nil
	}
	var have string
	err = tx.QueryRow(ctx,
		`SELECT counter FROM signer_counter_watermark WHERE record_key = $1`,
		recordKey(key, scope)).Scan(&have)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("counter watermark lookup: %w", err)
	}
	return decodeStoredCounter(have)
}

func decodeStoredCounter(have string) (uint64, bool, error) {
	v, err := counterDecode(have)
	if err != nil {
		return 0, false, fmt.Errorf(
			"counter watermark: corrupt stored counter %q",
			have,
		)
	}
	return v, true, nil
}
