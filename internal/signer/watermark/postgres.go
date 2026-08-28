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
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Compile-time proof PostgresWatermark satisfies both guard interfaces and the
// readiness Pinger.
var (
	_ Watermark        = (*PostgresWatermark)(nil)
	_ CounterWatermark = (*PostgresWatermark)(nil)
	_ Pinger           = (*PostgresWatermark)(nil)
)

// PostgresWatermark is a durable, shared Watermark and CounterWatermark backed
// by PostgreSQL via the pure-Go pgx driver (no CGO). A single Postgres instance
// shared by every signer replica is what lets the anti-double-sign guards hold
// across an HA deployment: the monotonic counter guard is enforced in one
// atomic SQL statement (advance-if-greater), so two replicas that concurrently
// try to advance the same key to the same counter cannot both succeed.
type PostgresWatermark struct {
	pool *pgxpool.Pool
}

// NewPostgresWatermark connects to Postgres at dsn (a libpq/pgx connection
// string or URL), creates the watermark tables if they do not exist, and
// returns a ready store. The dsn must be sourced from the environment by the
// caller; it commonly contains credentials and is never logged.
func NewPostgresWatermark(ctx context.Context, dsn string) (*PostgresWatermark, error) {
	if dsn == "" {
		return nil, errors.New("postgres watermark: empty dsn")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres watermark pool: %w", err)
	}
	s := &PostgresWatermark{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// NewPostgresWatermarkFromPool wraps an existing pool. It is used by tests that
// need two independent pools (simulating separate replicas) against the same
// database. The schema is initialized on the provided pool.
func NewPostgresWatermarkFromPool(ctx context.Context, pool *pgxpool.Pool) (*PostgresWatermark, error) {
	s := &PostgresWatermark{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *PostgresWatermark) initSchema(ctx context.Context) error {
	// signer_watermark records the payload digest per (key, scope) for
	// divergent-payload detection. signer_counter_watermark records the highest
	// monotonic counter per (key, scope). counter is a big-endian, fixed-width
	// hex string so that a lexicographic (TEXT) comparison equals numeric
	// ordering, identical to the sqlite store's encoding — no lossy
	// uint64->int64 conversion is needed.
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS signer_watermark (
			record_key   TEXT PRIMARY KEY,
			payload_hash TEXT NOT NULL,
			signed_at    BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
		)`,
		`CREATE TABLE IF NOT EXISTS signer_counter_watermark (
			record_key TEXT PRIMARY KEY,
			counter    TEXT NOT NULL,
			updated_at BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
		)`,
	}
	for _, q := range stmts {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("create postgres watermark schema: %w", err)
		}
	}
	return nil
}

// Close releases the underlying connection pool.
func (s *PostgresWatermark) Close() { s.pool.Close() }

// Ping verifies the Postgres backend can write both watermark tables. The
// readiness writes run in a transaction that is always rolled back.
func (s *PostgresWatermark) Ping(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin watermark readiness transaction: %w", err)
	}
	rolledBack := false
	defer func(rollbackBase context.Context) {
		if rolledBack {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(rollbackBase, time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}(context.WithoutCancel(ctx))

	if _, err := tx.Exec(ctx, `
		INSERT INTO signer_watermark (record_key, payload_hash)
		VALUES ($1, $2)
		ON CONFLICT (record_key) DO UPDATE
		SET payload_hash = signer_watermark.payload_hash
	`, readinessProbeRecordKey, readinessProbePayloadHash); err != nil {
		return fmt.Errorf("write payload watermark readiness probe: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO signer_counter_watermark (record_key, counter)
		VALUES ($1, $2)
		ON CONFLICT (record_key) DO UPDATE
		SET counter = signer_counter_watermark.counter
	`, readinessProbeRecordKey, readinessProbeCounter); err != nil {
		return fmt.Errorf("write counter watermark readiness probe: %w", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		return fmt.Errorf("rollback watermark readiness transaction: %w", err)
	}
	rolledBack = true
	return nil
}

func (s *PostgresWatermark) Check(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error {
	d := digest(payload)
	want := hex.EncodeToString(d[:])
	var have string
	err := s.pool.QueryRow(ctx,
		`SELECT payload_hash FROM signer_watermark WHERE record_key = $1`,
		recordKey(key, scope)).Scan(&have)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("watermark check: %w", err)
	}
	if have != want {
		return ErrConflict
	}
	return nil
}

func (s *PostgresWatermark) CheckAndCommit(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error {
	// Single atomic upsert mirroring the sqlite store: insert when absent, else
	// keep the existing row only when the payload matches. A divergent payload
	// makes the guarded DO UPDATE a no-op so RETURNING yields no row -> conflict.
	d := digest(payload)
	want := hex.EncodeToString(d[:])
	var have string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO signer_watermark (record_key, payload_hash) VALUES ($1, $2)
		 ON CONFLICT (record_key) DO UPDATE SET payload_hash = EXCLUDED.payload_hash
		 WHERE signer_watermark.payload_hash = EXCLUDED.payload_hash
		 RETURNING payload_hash`,
		recordKey(key, scope), want).Scan(&have)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("watermark check and commit: %w", err)
	}
	if have != want {
		return ErrConflict
	}
	return nil
}

func (s *PostgresWatermark) Commit(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error {
	d := digest(payload)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO signer_watermark (record_key, payload_hash) VALUES ($1, $2)
		 ON CONFLICT (record_key) DO NOTHING`,
		recordKey(key, scope), hex.EncodeToString(d[:]))
	if err != nil {
		return fmt.Errorf("watermark commit: %w", err)
	}
	return nil
}

func (s *PostgresWatermark) CounterFor(ctx context.Context, key backend.KeyHash, scope string) (uint64, bool, error) {
	var have string
	err := s.pool.QueryRow(ctx,
		`SELECT counter FROM signer_counter_watermark WHERE record_key = $1`,
		recordKey(key, scope)).Scan(&have)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("counter watermark lookup: %w", err)
	}
	v, err := counterDecode(have)
	if err != nil {
		return 0, false, fmt.Errorf("counter watermark: corrupt stored counter %q", have)
	}
	return v, true, nil
}

func (s *PostgresWatermark) CheckAndCommitCounter(ctx context.Context, key backend.KeyHash, scope string, counter uint64) error {
	// Atomic advance-if-greater in a SINGLE statement — the core of HA safety.
	// The row is inserted when absent, else updated only when the new counter is
	// strictly greater. When the guard fails the DO UPDATE is a no-op and
	// RETURNING yields no row (pgx.ErrNoRows) -> regression/conflict. Because the
	// compare-and-set happens atomically in Postgres, two replicas racing with
	// the same counter for the same key cannot both advance it.
	want := counterEncode(counter)
	var have string
	// The counter column is compared with an explicit "C" collation so the
	// advance-if-greater guard always evaluates in raw byte order, matching
	// counterEncode's big-endian hex encoding. Without this, a database
	// (or column) using a non-"C" default collation could order the hex
	// strings by locale rules instead of byte value, letting a lower counter
	// advance or rejecting a valid higher one.
	err := s.pool.QueryRow(ctx,
		`INSERT INTO signer_counter_watermark (record_key, counter) VALUES ($1, $2)
		 ON CONFLICT (record_key) DO UPDATE SET counter = EXCLUDED.counter, updated_at = extract(epoch from now())::bigint
		 WHERE (EXCLUDED.counter COLLATE "C") > (signer_counter_watermark.counter COLLATE "C")
		 RETURNING counter`,
		recordKey(key, scope), want).Scan(&have)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCounterRegression
	}
	if err != nil {
		return fmt.Errorf("counter watermark check and commit: %w", err)
	}
	if have != want {
		return ErrCounterRegression
	}
	return nil
}
