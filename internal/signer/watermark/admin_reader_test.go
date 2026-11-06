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
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
)

// checkCounterReader requires reader to report no record for an unwritten
// key and the stored value for a written one.
func checkCounterReader(
	t *testing.T,
	w CounterWatermark,
	reader CounterReader,
	written, unwritten backend.KeyHash,
) {
	t.Helper()
	ctx := context.Background()
	if err := w.CheckAndRaiseFloor(ctx, written, "floor", 7); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := reader.CounterFor(ctx, unwritten, "floor"); err != nil ||
		ok {
		t.Fatalf("unwritten key = (%d, %v, %v), want no record", v, ok, err)
	}
	if v, ok, err := reader.CounterFor(ctx, written, "floor"); err != nil ||
		!ok ||
		v != 7 {
		t.Fatalf("written key = (%d, %v, %v), want 7", v, ok, err)
	}
}

func TestSqliteCounterReader(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wm.db")
	w, err := NewSqliteWatermark(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	r, err := OpenSqliteCounterReader(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	var a, b backend.KeyHash
	a[0], b[0] = 1, 2
	checkCounterReader(t, w, r, a, b)
}

func TestSqliteCounterReader_NoTable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wm.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenSqliteCounterReader(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	var k backend.KeyHash
	if v, ok, err := r.CounterFor(context.Background(), k, "floor"); err != nil ||
		ok {
		t.Fatalf("empty store = (%d, %v, %v), want no record", v, ok, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Fatalf("read-only open wrote to the store: %v %v", fi, err)
	}
}

func TestSqliteCounterReader_MissingFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "absent.db")
	if r, err := OpenSqliteCounterReader(path); err == nil {
		_ = r.Close()
		t.Fatal("opened a missing file")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("read-only open created the file")
	}
}

func TestPostgresCounterReader(t *testing.T) {
	t.Parallel()
	dsn := testPGDSN(t)
	w := newTestPG(t, dsn)
	r, err := OpenPostgresCounterReader(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	checkCounterReader(t, w, r, randKey(t), randKey(t))
}

// TestSqliteCounterReader_WriterClosed reads a WAL store after its writer has
// closed, as when the signer is stopped.
func TestSqliteCounterReader_WriterClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wm.db")
	w, err := NewSqliteWatermark(path)
	if err != nil {
		t.Fatal(err)
	}
	var k backend.KeyHash
	k[0] = 1
	ctx := context.Background()
	if err := w.CheckAndRaiseFloor(ctx, k, "floor", 7); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := OpenSqliteCounterReader(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if v, ok, err := r.CounterFor(ctx, k, "floor"); err != nil || !ok ||
		v != 7 {
		t.Fatalf("got (%d, %v, %v), want 7", v, ok, err)
	}
}
