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
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// CounterSet is one scope's value in an administrative counter reset.
type CounterSet struct {
	Scope string
	Value uint64
}

// CounterAdmin is the administrative counterpart of CounterWatermark. It is
// deliberately a separate interface so it is never reachable through the
// signing path: only an operator command asserts it.
type CounterAdmin interface {
	// AdminResetCounters unconditionally records each set value, lower or
	// higher than the stored one, and deletes every clear scope, for key in
	// one atomic transaction. It performs none of the monotonic checks.
	AdminResetCounters(
		ctx context.Context,
		key backend.KeyHash,
		set []CounterSet,
		clear []string,
	) error
}

var (
	_ CounterAdmin = (*SqliteWatermark)(nil)
	_ CounterAdmin = (*PostgresWatermark)(nil)
)

// validateAdminReset rejects an empty reset and a scope that is both set and
// cleared.
func validateAdminReset(set []CounterSet, clear []string) error {
	if len(set) == 0 && len(clear) == 0 {
		return errors.New("counter watermark: empty admin reset")
	}
	seen := make(map[string]struct{}, len(set))
	for _, s := range set {
		seen[s.Scope] = struct{}{}
	}
	for _, c := range clear {
		if _, dup := seen[c]; dup {
			return fmt.Errorf(
				"counter watermark: scope %q is both set and cleared", c,
			)
		}
	}
	return nil
}
