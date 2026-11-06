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
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	_ "modernc.org/sqlite"
)

// SqliteWatermark is a durable file-backed Watermark using pure-Go sqlite.
type SqliteWatermark struct {
	db *sql.DB
}

// NewSqliteWatermark opens (creating if needed) a sqlite watermark store at path.
func NewSqliteWatermark(path string) (*SqliteWatermark, error) {
	db, err := sql.Open(
		"sqlite",
		path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
	)
	if err != nil {
		return nil, fmt.Errorf("open watermark db: %w", err)
	}
	// SQLite only supports one writer at a time. Limiting to a single
	// connection ensures all PRAGMAs remain in effect, since they are
	// per-connection settings.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS watermark (
		record_key TEXT PRIMARY KEY,
		payload_hash TEXT NOT NULL,
		signed_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
	)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create watermark table: %w", err)
	}
	// counter_watermark stores the highest monotonic counter (e.g. opcert issue
	// counter) per (key, scope). counter is a big-endian, fixed-width hex string
	// so that a lexicographic (default TEXT) comparison equals numeric ordering.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS counter_watermark (
		record_key TEXT PRIMARY KEY,
		counter TEXT NOT NULL,
		updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
	)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create counter_watermark table: %w", err)
	}
	return &SqliteWatermark{db: db}, nil
}

// Close closes the underlying database.
func (s *SqliteWatermark) Close() error { return s.db.Close() }

// Ping verifies the sqlite database can write both watermark tables. The
// readiness writes run in a transaction that is always rolled back.
func (s *SqliteWatermark) Ping(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin watermark readiness transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO watermark (record_key, payload_hash)
		VALUES (?, ?)
		ON CONFLICT(record_key) DO UPDATE
		SET payload_hash = watermark.payload_hash
	`, readinessProbeRecordKey, readinessProbePayloadHash); err != nil {
		return fmt.Errorf("write payload watermark readiness probe: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO counter_watermark (record_key, counter)
		VALUES (?, ?)
		ON CONFLICT(record_key) DO UPDATE
		SET counter = counter_watermark.counter
	`, readinessProbeRecordKey, readinessProbeCounter); err != nil {
		return fmt.Errorf("write counter watermark readiness probe: %w", err)
	}
	if err := tx.Rollback(); err != nil {
		return fmt.Errorf("rollback watermark readiness transaction: %w", err)
	}
	return nil
}

func (s *SqliteWatermark) Check(
	ctx context.Context,
	key backend.KeyHash,
	scope string,
	payload []byte,
) error {
	d := digest(payload)
	want := hex.EncodeToString(d[:])
	var have string
	err := s.db.QueryRowContext(ctx, `SELECT payload_hash FROM watermark WHERE record_key = ?`, recordKey(key, scope)).
		Scan(&have)
	if errors.Is(err, sql.ErrNoRows) {
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

func (s *SqliteWatermark) CheckAndCommit(
	ctx context.Context,
	key backend.KeyHash,
	scope string,
	payload []byte,
) error {
	d := digest(payload)
	want := hex.EncodeToString(d[:])
	var have string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO watermark (record_key, payload_hash) VALUES (?, ?)
		 ON CONFLICT(record_key) DO UPDATE SET payload_hash = excluded.payload_hash
		 WHERE watermark.payload_hash = excluded.payload_hash
		 RETURNING payload_hash`,
		recordKey(key, scope), want).Scan(&have)
	if errors.Is(err, sql.ErrNoRows) {
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

func (s *SqliteWatermark) Commit(
	ctx context.Context,
	key backend.KeyHash,
	scope string,
	payload []byte,
) error {
	d := digest(payload)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO watermark (record_key, payload_hash) VALUES (?, ?)
		 ON CONFLICT(record_key) DO NOTHING`,
		recordKey(key, scope), hex.EncodeToString(d[:]))
	if err != nil {
		return fmt.Errorf("watermark commit: %w", err)
	}
	return nil
}

func (s *SqliteWatermark) CounterFor(
	ctx context.Context,
	key backend.KeyHash,
	scope string,
) (uint64, bool, error) {
	var have string
	err := s.db.QueryRowContext(ctx,
		`SELECT counter FROM counter_watermark WHERE record_key = ?`,
		recordKey(key, scope)).Scan(&have)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("counter watermark lookup: %w", err)
	}
	v, err := counterDecode(have)
	if err != nil {
		return 0, false, fmt.Errorf(
			"counter watermark: corrupt stored counter %q",
			have,
		)
	}
	return v, true, nil
}

func (s *SqliteWatermark) CheckAndCommitCounter(
	ctx context.Context,
	key backend.KeyHash,
	scope string,
	counter uint64,
) error {
	// Single atomic upsert: insert when no row exists, else update only when the
	// new counter is strictly greater. When the guard fails the DO UPDATE is a
	// no-op and RETURNING yields no row (sql.ErrNoRows) -> regression. This is the
	// same pattern the payload watermark uses, so two concurrent callers with the
	// same counter cannot both commit.
	want := counterEncode(counter)
	var have string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO counter_watermark (record_key, counter) VALUES (?, ?)
		 ON CONFLICT(record_key) DO UPDATE SET counter = excluded.counter, updated_at = strftime('%s','now')
		 WHERE excluded.counter > counter_watermark.counter
		 RETURNING counter`,
		recordKey(key, scope), want).Scan(&have)
	if errors.Is(err, sql.ErrNoRows) {
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

func (s *SqliteWatermark) CheckAndRaiseFloor(
	ctx context.Context,
	key backend.KeyHash,
	scope string,
	value uint64,
) error {
	// The same single-statement upsert as CheckAndCommitCounter, with the
	// guard relaxed to >= so an unchanged floor is accepted.
	want := counterEncode(value)
	var have string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO counter_watermark (record_key, counter) VALUES (?, ?)
		 ON CONFLICT(record_key) DO UPDATE SET counter = excluded.counter, updated_at = strftime('%s','now')
		 WHERE excluded.counter >= counter_watermark.counter
		 RETURNING counter`,
		recordKey(key, scope), want).Scan(&have)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCounterRegression
	}
	if err != nil {
		return fmt.Errorf("counter watermark raise floor: %w", err)
	}
	if have != want {
		return ErrCounterRegression
	}
	return nil
}

// sqliteCounterUpsert returns the guarded upsert for op and its arguments
// (after the record key and encoded value). The guards match the single-scope
// methods.
func sqliteCounterUpsert(op CounterOp) (string, []any) {
	var guard string
	var extra []any
	switch op.Kind {
	case CounterFloor:
		guard = `excluded.counter >= counter_watermark.counter`
	case CounterFloorFrom:
		guard = `excluded.counter >= counter_watermark.counter AND counter_watermark.counter >= ?`
		extra = []any{counterEncode(op.Min)}
	case CounterStrict:
		guard = `excluded.counter > counter_watermark.counter`
	case CounterEqual:
		// checked by its own read, never upserted
		guard = `false`
	default:
		guard = `false`
	}
	return `INSERT INTO counter_watermark (record_key, counter) VALUES (?, ?)
		 ON CONFLICT(record_key) DO UPDATE SET counter = excluded.counter, updated_at = strftime('%s','now')
		 WHERE ` + guard + `
		 RETURNING counter`, extra
}

// CheckAndCommitCounters applies every op's guarded upsert in one transaction
// and rolls back on the first refusal.
func (s *SqliteWatermark) CheckAndCommitCounters(
	ctx context.Context,
	key backend.KeyHash,
	ops ...CounterOp,
) error {
	if err := validateCounterOps(ops); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("counter watermark begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, op := range ops {
		if op.Kind == CounterEqual {
			if err := sqliteRequireCounter(ctx, tx, key, op); err != nil {
				return err
			}
			continue
		}
		q, extra := sqliteCounterUpsert(op)
		want := counterEncode(op.Value)
		var have string
		err := tx.QueryRowContext(ctx, q, append([]any{recordKey(key, op.Scope), want}, extra...)...).
			Scan(&have)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && have != want) {
			return &CounterRegressionError{Scope: op.Scope}
		}
		if err != nil {
			return fmt.Errorf("counter watermark check and commit: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("counter watermark commit: %w", err)
	}
	return nil
}

// sqliteRequireCounter checks a CounterEqual op inside tx. The insert of a
// missing record at 0 is a write, so the transaction holds SQLite's write lock
// before it reads, and a reset in another process cannot slip in between.
func sqliteRequireCounter(
	ctx context.Context,
	tx *sql.Tx,
	key backend.KeyHash,
	op CounterOp,
) error {
	rk := recordKey(key, op.Scope)
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO counter_watermark (record_key, counter) VALUES (?, ?)`,
		rk, counterEncode(0)); err != nil {
		return fmt.Errorf("counter watermark check and commit: %w", err)
	}
	var have string
	if err := tx.QueryRowContext(ctx,
		`SELECT counter FROM counter_watermark WHERE record_key = ?`,
		rk).Scan(&have); err != nil {
		return fmt.Errorf("counter watermark check and commit: %w", err)
	}
	if have != counterEncode(op.Value) {
		return &CounterRegressionError{Scope: op.Scope}
	}
	return nil
}
