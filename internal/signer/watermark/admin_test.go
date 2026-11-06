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
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

type adminStore interface {
	CounterWatermark
	CounterAdmin
}

func checkAdminReset(t *testing.T, wm adminStore, a, b backend.KeyHash) {
	t.Helper()
	ctx := context.Background()
	for _, k := range []backend.KeyHash{a, b} {
		for scope, v := range map[string]uint64{"floor": 12, "issued": 9, "keep": 5} {
			if err := wm.CheckAndRaiseFloor(ctx, k, scope, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	// lower than stored, plus a clear of a scope with a record and one without
	err := wm.AdminResetCounters(
		ctx, a,
		[]CounterSet{{Scope: "floor", Value: 10}, {Scope: "new", Value: 3}},
		[]string{"issued", "absent"},
	)
	if err != nil {
		t.Fatalf("AdminResetCounters: %v", err)
	}
	want := map[string]struct {
		v  uint64
		ok bool
	}{
		"floor": {
			10,
			true,
		}, "new": {3, true}, "issued": {0, false}, "keep": {5, true},
	}
	for scope, w := range want {
		v, ok, err := wm.CounterFor(ctx, a, scope)
		if err != nil || ok != w.ok || v != w.v {
			t.Fatalf(
				"a/%s = (%d, %v, %v), want (%d, %v)",
				scope,
				v,
				ok,
				err,
				w.v,
				w.ok,
			)
		}
	}
	for scope, wv := range map[string]uint64{"floor": 12, "issued": 9, "keep": 5} {
		v, ok, _ := wm.CounterFor(ctx, b, scope)
		if !ok || v != wv {
			t.Fatalf("other key %s = (%d, %v), want %d", scope, v, ok, wv)
		}
	}
	// A reset to the same state again is accepted.
	if err := wm.AdminResetCounters(ctx, a, []CounterSet{{Scope: "floor", Value: 10}}, nil); err != nil {
		t.Fatalf("repeat reset: %v", err)
	}
}

func TestAdminResetCounters_Sqlite(t *testing.T) {
	t.Parallel()
	wm, err := NewSqliteWatermark(filepath.Join(t.TempDir(), "wm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wm.Close() })
	var a, b backend.KeyHash
	a[0], b[0] = 1, 2
	checkAdminReset(t, wm, a, b)
}

func TestAdminResetCounters_Postgres(t *testing.T) {
	t.Parallel()
	wm := newTestPG(t, testPGDSN(t))
	checkAdminReset(t, wm, randKey(t), randKey(t))
}
