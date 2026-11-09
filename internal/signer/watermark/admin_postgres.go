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
	"fmt"
	"math"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/jackc/pgx/v5"
)

// AdminResetCounters applies the reset in one transaction.
func (s *PostgresWatermark) AdminResetCounters(
	ctx context.Context,
	key backend.KeyHash,
	set []CounterSet,
	clear []string,
	bump ...string,
) error {
	if err := validateAdminReset(set, clear, bump); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("counter watermark admin reset: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, b := range bump {
		if err := postgresBumpCounter(ctx, tx, key, b); err != nil {
			return err
		}
	}
	for _, c := range set {
		if _, err := tx.Exec(ctx,
			`INSERT INTO signer_counter_watermark (record_key, counter) VALUES ($1, $2)
			 ON CONFLICT (record_key) DO UPDATE SET counter = EXCLUDED.counter, updated_at = extract(epoch from now())::bigint`,
			recordKey(key, c.Scope), counterEncode(c.Value)); err != nil {
			return fmt.Errorf("counter watermark admin reset: set: %w", err)
		}
	}
	for _, c := range clear {
		if _, err := tx.Exec(ctx,
			`DELETE FROM signer_counter_watermark WHERE record_key = $1`,
			recordKey(key, c)); err != nil {
			return fmt.Errorf("counter watermark admin reset: clear: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("counter watermark admin reset: commit: %w", err)
	}
	return nil
}

// postgresBumpCounter adds one to the scope's counter, from 0 if absent. The
// FOR UPDATE read waits for every commit holding the row FOR SHARE and blocks
// new ones until the reset ends. It runs before any other row is touched, the
// same order CheckAndCommitCounters takes.
func postgresBumpCounter(
	ctx context.Context,
	tx pgx.Tx,
	key backend.KeyHash,
	scope string,
) error {
	rk := recordKey(key, scope)
	if _, err := tx.Exec(ctx,
		`INSERT INTO signer_counter_watermark (record_key, counter) VALUES ($1, $2)
		 ON CONFLICT (record_key) DO NOTHING`,
		rk, counterEncode(0)); err != nil {
		return fmt.Errorf("counter watermark admin reset: bump: %w", err)
	}
	var have string
	if err := tx.QueryRow(ctx,
		`SELECT counter FROM signer_counter_watermark WHERE record_key = $1 FOR UPDATE`,
		rk).Scan(&have); err != nil {
		return fmt.Errorf("counter watermark admin reset: bump: %w", err)
	}
	v, err := counterDecode(have)
	if err != nil || v == math.MaxUint64 {
		return fmt.Errorf(
			"counter watermark admin reset: bump %q: bad value",
			scope,
		)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE signer_counter_watermark SET counter = $1, updated_at = extract(epoch from now())::bigint WHERE record_key = $2`,
		counterEncode(v+1), rk); err != nil {
		return fmt.Errorf("counter watermark admin reset: bump: %w", err)
	}
	return nil
}
