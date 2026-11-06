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

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// AdminResetCounters applies the reset in one transaction. The store holds a
// single connection, so the transaction contains only writes.
func (s *SqliteWatermark) AdminResetCounters(
	ctx context.Context,
	key backend.KeyHash,
	set []CounterSet,
	clear []string,
) error {
	if err := validateAdminReset(set, clear); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("counter watermark admin reset: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, c := range set {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO counter_watermark (record_key, counter) VALUES (?, ?)
			 ON CONFLICT(record_key) DO UPDATE SET counter = excluded.counter, updated_at = strftime('%s','now')`,
			recordKey(key, c.Scope), counterEncode(c.Value)); err != nil {
			return fmt.Errorf("counter watermark admin reset: set: %w", err)
		}
	}
	for _, c := range clear {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM counter_watermark WHERE record_key = ?`,
			recordKey(key, c)); err != nil {
			return fmt.Errorf("counter watermark admin reset: clear: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("counter watermark admin reset: commit: %w", err)
	}
	return nil
}
