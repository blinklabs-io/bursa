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
	"encoding/binary"
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
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
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

func (s *SqliteWatermark) Check(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error {
	d := digest(payload)
	want := hex.EncodeToString(d[:])
	var have string
	err := s.db.QueryRowContext(ctx, `SELECT payload_hash FROM watermark WHERE record_key = ?`, recordKey(key, scope)).Scan(&have)
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

func (s *SqliteWatermark) CheckAndCommit(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error {
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

func (s *SqliteWatermark) Commit(ctx context.Context, key backend.KeyHash, scope string, payload []byte) error {
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

func (s *SqliteWatermark) CounterFor(ctx context.Context, key backend.KeyHash, scope string) (uint64, bool, error) {
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
	raw, err := hex.DecodeString(have)
	if err != nil || len(raw) != 8 {
		return 0, false, fmt.Errorf("counter watermark: corrupt stored counter %q", have)
	}
	return binary.BigEndian.Uint64(raw), true, nil
}

func (s *SqliteWatermark) CheckAndCommitCounter(ctx context.Context, key backend.KeyHash, scope string, counter uint64) error {
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
