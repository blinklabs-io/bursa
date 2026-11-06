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

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
// creates no table and runs no migration.
type SqliteCounterReader struct {
	db *sql.DB
}

// OpenSqliteCounterReader opens the SQLite store at path read-only. The file
// must exist.
func OpenSqliteCounterReader(path string) (*SqliteCounterReader, error) {
	u := url.URL{
		Scheme:   "file",
		Path:     path,
		RawQuery: "mode=ro&_pragma=busy_timeout(5000)",
	}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("open watermark db read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open watermark db read-only: %w", err)
	}
	return &SqliteCounterReader{db: db}, nil
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
