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

package kesagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ KeyStore = (*PostgresKeyStore)(nil)

// PostgresKeyStore is a KeyStore in PostgreSQL, in the kes_agent_key table
// of the database the shared guard uses. Each (pool_key, network) has at most
// one row per state: 'staged' and 'installed'.
type PostgresKeyStore struct {
	pool *pgxpool.Pool
}

// keyStoreAdvisoryLockID is the advisory lock key held while the
// kes_agent_key table is created. Its value is arbitrary but fixed, and
// differs from the watermark store's.
const keyStoreAdvisoryLockID int64 = 0x62757273615f6b73 // "bursa_ks"

// NewPostgresKeyStore creates the kes_agent_key table in pool's database if
// it is missing and returns the store. pool is typically the shared guard
// store's (watermark.PostgresWatermark.Pool), so it has passed the same
// connection checks; the caller keeps ownership of it.
func NewPostgresKeyStore(
	ctx context.Context,
	pool *pgxpool.Pool,
) (*PostgresKeyStore, error) {
	if pool == nil {
		return nil, errors.New("kesagent: nil PostgreSQL pool for the key store")
	}
	s := &PostgresKeyStore{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *PostgresKeyStore) initSchema(ctx context.Context) error {
	// Replicas starting together on an empty database would race on CREATE
	// TABLE IF NOT EXISTS; the transaction-scoped advisory lock makes them
	// take turns, as the watermark store does for its tables.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("kesagent: begin key store schema transaction: %w", err)
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock($1)`,
		keyStoreAdvisoryLockID,
	); err != nil {
		return fmt.Errorf("kesagent: lock key store schema: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS kes_agent_key (
		pool_key      TEXT   NOT NULL,
		network       TEXT   NOT NULL,
		state         TEXT   NOT NULL CHECK (state IN ('staged', 'installed')),
		kes_vkey      BYTEA  NOT NULL,
		depth         BIGINT NOT NULL,
		sealed_period BIGINT NOT NULL,
		sealed_key    BYTEA  NOT NULL,
		opcert        BYTEA,
		generation    BIGINT NOT NULL DEFAULT 0,
		updated_at    BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,
		PRIMARY KEY (pool_key, network, state)
	)`); err != nil {
		return fmt.Errorf("kesagent: create key store schema: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("kesagent: commit key store schema: %w", err)
	}
	return nil
}

// rollback ends tx if it is still open; after a commit it does nothing.
func rollback(ctx context.Context, tx pgx.Tx) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	_ = tx.Rollback(rctx)
}

// toInt64 converts a depth or period for a BIGINT column.
func toInt64(name string, v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("kesagent: %s %d does not fit the key store", name, v)
	}
	return int64(v), nil // #nosec G115 -- checked above
}

// toUint64 converts a BIGINT column read back from the store.
func toUint64(name string, v int64) (uint64, error) {
	if v < 0 {
		return 0, fmt.Errorf("kesagent: key store holds a negative %s", name)
	}
	return uint64(v), nil // #nosec G115 -- checked above
}

// PutStaged replaces the profile's staged record.
func (s *PostgresKeyStore) PutStaged(
	ctx context.Context,
	pool, network string,
	rec SealedKey,
) error {
	depth, err := toInt64("depth", rec.Depth)
	if err != nil {
		return err
	}
	period, err := toInt64("sealed period", rec.SealedPeriod)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO kes_agent_key
			(pool_key, network, state, kes_vkey, depth, sealed_period, sealed_key)
		VALUES ($1, $2, 'staged', $3, $4, $5, $6)
		ON CONFLICT (pool_key, network, state) DO UPDATE SET
			kes_vkey      = EXCLUDED.kes_vkey,
			depth         = EXCLUDED.depth,
			sealed_period = EXCLUDED.sealed_period,
			sealed_key    = EXCLUDED.sealed_key,
			updated_at    = extract(epoch from now())::bigint`,
		pool, network, rec.KESVKey, depth, period, rec.Sealed,
	)
	if err != nil {
		return fmt.Errorf("kesagent: write staged KES key: %w", err)
	}
	return nil
}

// Staged returns the profile's staged record.
func (s *PostgresKeyStore) Staged(
	ctx context.Context,
	pool, network string,
) (SealedKey, bool, error) {
	return s.get(ctx, s.pool, pool, network, "staged", "")
}

// Installed returns the profile's installed record.
func (s *PostgresKeyStore) Installed(
	ctx context.Context,
	pool, network string,
) (SealedKey, bool, error) {
	return s.get(ctx, s.pool, pool, network, "installed", "")
}

// querier is a pool or a transaction.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// get reads one record; suffix is appended to the query (" FOR UPDATE").
func (s *PostgresKeyStore) get(
	ctx context.Context,
	q querier,
	pool, network, state, suffix string,
) (SealedKey, bool, error) {
	var (
		rec           SealedKey
		depth, period int64
		generation    int64
	)
	err := q.QueryRow(ctx, `
		SELECT kes_vkey, depth, sealed_period, sealed_key, opcert, generation
		FROM kes_agent_key
		WHERE pool_key = $1 AND network = $2 AND state = $3`+suffix,
		pool, network, state,
	).Scan(&rec.KESVKey, &depth, &period, &rec.Sealed, &rec.OpCert, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return SealedKey{}, false, nil
	}
	if err != nil {
		return SealedKey{}, false, fmt.Errorf(
			"kesagent: read %s KES key: %w",
			state,
			err,
		)
	}
	if rec.Depth, err = toUint64("depth", depth); err != nil {
		return SealedKey{}, false, err
	}
	if rec.SealedPeriod, err = toUint64("sealed period", period); err != nil {
		return SealedKey{}, false, err
	}
	if rec.Generation, err = toUint64("generation", generation); err != nil {
		return SealedKey{}, false, err
	}
	return rec, true, nil
}

// Install moves the staged record to installed in one transaction. The
// staged row is locked first, so of two replicas installing at once the
// second waits, then finds no staged row and compares against what the first
// installed.
func (s *PostgresKeyStore) Install(
	ctx context.Context,
	pool, network string,
	kesVKey, opcert []byte,
) (uint64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("kesagent: begin KES key install: %w", err)
	}
	defer rollback(ctx, tx)
	staged, ok, err := s.get(ctx, tx, pool, network, "staged", " FOR UPDATE")
	if err != nil {
		return 0, err
	}
	if !ok {
		installed, ok, err := s.get(ctx, tx, pool, network, "installed", "")
		if err != nil {
			return 0, err
		}
		return alreadyInstalled(installed, ok, kesVKey, opcert)
	}
	if !bytes.Equal(staged.KESVKey, kesVKey) {
		return 0, ErrOpCertKESVK
	}
	depth, err := toInt64("depth", staged.Depth)
	if err != nil {
		return 0, err
	}
	period, err := toInt64("sealed period", staged.SealedPeriod)
	if err != nil {
		return 0, err
	}
	var generation int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO kes_agent_key
			(pool_key, network, state, kes_vkey, depth, sealed_period,
			 sealed_key, opcert, generation)
		VALUES ($1, $2, 'installed', $3, $4, $5, $6, $7, 1)
		ON CONFLICT (pool_key, network, state) DO UPDATE SET
			kes_vkey      = EXCLUDED.kes_vkey,
			depth         = EXCLUDED.depth,
			sealed_period = EXCLUDED.sealed_period,
			sealed_key    = EXCLUDED.sealed_key,
			opcert        = EXCLUDED.opcert,
			generation    = kes_agent_key.generation + 1,
			updated_at    = extract(epoch from now())::bigint
		RETURNING generation`,
		pool, network, staged.KESVKey, depth, period, staged.Sealed, opcert,
	).Scan(&generation); err != nil {
		return 0, fmt.Errorf("kesagent: write installed KES key: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM kes_agent_key
		WHERE pool_key = $1 AND network = $2 AND state = 'staged'`,
		pool, network,
	); err != nil {
		return 0, fmt.Errorf("kesagent: clear staged KES key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("kesagent: commit KES key install: %w", err)
	}
	return toUint64("generation", generation)
}

// alreadyInstalled decides an install that found no staged record: success
// when kesVKey is installed with the same opcert, otherwise the reason.
func alreadyInstalled(
	installed SealedKey,
	ok bool,
	kesVKey, opcert []byte,
) (uint64, error) {
	switch {
	case !ok || !bytes.Equal(installed.KESVKey, kesVKey):
		return 0, ErrNoStagedKey
	case !bytes.Equal(installed.OpCert, opcert):
		return 0, ErrKeyAlreadyInstalled
	default:
		return installed.Generation, nil
	}
}
