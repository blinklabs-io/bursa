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
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgDSNEnv is the environment variable holding the Postgres connection string
// used by the runtime tests. When unset the runtime tests skip.
const pgDSNEnv = "BURSA_TEST_POSTGRES_DSN"

// testPGDSN returns the configured Postgres DSN or skips the test.
func testPGDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(pgDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping Postgres runtime tests", pgDSNEnv)
	}
	return dsn
}

// newTestPG opens a Postgres store or fails the test.
func newTestPG(t *testing.T, dsn string) *PostgresWatermark {
	t.Helper()
	wm, err := NewPostgresWatermark(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgresWatermark: %v", err)
	}
	t.Cleanup(wm.Close)
	return wm
}

// randKey returns a random key hash so concurrently-run tests against a shared
// database do not collide on (key, scope).
func randKey(t *testing.T) backend.KeyHash {
	t.Helper()
	var k backend.KeyHash
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestPostgres_PayloadDivergence(t *testing.T) {
	dsn := testPGDSN(t)
	wm := newTestPG(t, dsn)
	ctx := context.Background()
	key := randKey(t)
	scope := "tx"

	if err := wm.Check(ctx, key, scope, []byte("A")); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if err := wm.CheckAndCommit(ctx, key, scope, []byte("A")); err != nil {
		t.Fatalf("check-and-commit A: %v", err)
	}
	// Same payload is idempotent.
	if err := wm.CheckAndCommit(ctx, key, scope, []byte("A")); err != nil {
		t.Fatalf("idempotent check-and-commit A: %v", err)
	}
	// Divergent payload conflicts on both Check and CheckAndCommit.
	if err := wm.Check(ctx, key, scope, []byte("B")); !errors.Is(err, ErrConflict) {
		t.Fatalf("Check divergent: want ErrConflict, got %v", err)
	}
	if err := wm.CheckAndCommit(ctx, key, scope, []byte("B")); !errors.Is(err, ErrConflict) {
		t.Fatalf("CheckAndCommit divergent: want ErrConflict, got %v", err)
	}
	// Commit is first-writer-wins: a divergent Commit keeps the original.
	if err := wm.Commit(ctx, key, scope, []byte("B")); err != nil {
		t.Fatalf("commit divergent (no-op expected): %v", err)
	}
	if err := wm.Check(ctx, key, scope, []byte("A")); err != nil {
		t.Fatalf("original payload must survive divergent commit: %v", err)
	}
}

func TestPostgres_CounterMonotonicity(t *testing.T) {
	dsn := testPGDSN(t)
	wm := newTestPG(t, dsn)
	ctx := context.Background()
	key := randKey(t)
	scope := "opcert-counter"

	if _, ok, err := wm.CounterFor(ctx, key, scope); err != nil || ok {
		t.Fatalf("CounterFor on empty: got (ok=%v, err=%v)", ok, err)
	}
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 5); err != nil {
		t.Fatalf("first commit at 5: %v", err)
	}
	if v, ok, err := wm.CounterFor(ctx, key, scope); err != nil || !ok || v != 5 {
		t.Fatalf("after first commit: got (v=%d, ok=%v, err=%v), want 5", v, ok, err)
	}
	// Equal and lower are regressions and record nothing.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 5); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("re-commit at 5: want ErrCounterRegression, got %v", err)
	}
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 4); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("commit at 4: want ErrCounterRegression, got %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != 5 {
		t.Fatalf("stored counter regressed to %d after rejected commits, want 5", v)
	}
	// Strictly greater advances, including a large jump past int64-relevant values.
	if err := wm.CheckAndCommitCounter(ctx, key, scope, 6); err != nil {
		t.Fatalf("commit at 6: %v", err)
	}
	const big = uint64(1) << 63 // exceeds math.MaxInt64; proves no lossy int64 cast
	if err := wm.CheckAndCommitCounter(ctx, key, scope, big); err != nil {
		t.Fatalf("commit at 2^63: %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, key, scope); v != big {
		t.Fatalf("after 2^63 jump: got %d, want %d", v, big)
	}
	// A value below 2^63 must now regress (ordering correct across the int64 boundary).
	if err := wm.CheckAndCommitCounter(ctx, key, scope, big-1); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("commit below high watermark: want ErrCounterRegression, got %v", err)
	}
}

func TestPostgres_CounterPerKeyIsolation(t *testing.T) {
	dsn := testPGDSN(t)
	wm := newTestPG(t, dsn)
	ctx := context.Background()
	keyA, keyB := randKey(t), randKey(t)
	scope := "opcert-counter"

	if err := wm.CheckAndCommitCounter(ctx, keyA, scope, 10); err != nil {
		t.Fatalf("keyA commit: %v", err)
	}
	if err := wm.CheckAndCommitCounter(ctx, keyB, scope, 1); err != nil {
		t.Fatalf("keyB commit at 1 must be independent of keyA: %v", err)
	}
	if v, _, _ := wm.CounterFor(ctx, keyA, scope); v != 10 {
		t.Fatalf("keyA counter changed to %d, want 10", v)
	}
	if v, _, _ := wm.CounterFor(ctx, keyB, scope); v != 1 {
		t.Fatalf("keyB counter %d, want 1", v)
	}
}

// TestPostgres_DurabilityAcrossReconnect proves records survive a full pool
// teardown and fresh reconnection — the shared store outlives any one replica.
func TestPostgres_DurabilityAcrossReconnect(t *testing.T) {
	dsn := testPGDSN(t)
	ctx := context.Background()
	key := randKey(t)

	wm1, err := NewPostgresWatermark(ctx, dsn)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	if err := wm1.Commit(ctx, key, "tx", []byte("payload-1")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := wm1.CheckAndCommitCounter(ctx, key, "opcert", 42); err != nil {
		t.Fatalf("counter commit: %v", err)
	}
	wm1.Close()

	wm2, err := NewPostgresWatermark(ctx, dsn)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer wm2.Close()
	if err := wm2.Check(ctx, key, "tx", []byte("payload-2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("payload must survive reconnect: want ErrConflict, got %v", err)
	}
	if v, ok, _ := wm2.CounterFor(ctx, key, "opcert"); !ok || v != 42 {
		t.Fatalf("counter must survive reconnect: got (v=%d, ok=%v), want 42", v, ok)
	}
}

// TestPostgres_ConcurrentAdvanceExactlyOneWins simulates two replicas (two
// independent pools) racing to advance the same key to the same counter. The
// atomic advance-if-greater guarantees exactly one wins.
func TestPostgres_ConcurrentAdvanceExactlyOneWins(t *testing.T) {
	dsn := testPGDSN(t)
	ctx := context.Background()
	key := randKey(t)
	scope := "opcert-counter"

	replicaA := newTestPG(t, dsn)
	replicaB := newTestPG(t, dsn)

	const attempts = 40
	for target := uint64(1); target <= attempts; target++ {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		stores := [2]*PostgresWatermark{replicaA, replicaB}
		for i := range stores {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = stores[i].CheckAndCommitCounter(ctx, key, scope, target)
			}(i)
		}
		close(start)
		wg.Wait()

		wins, regressions := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrCounterRegression):
				regressions++
			default:
				t.Fatalf("target %d: unexpected error: %v", target, err)
			}
		}
		if wins != 1 || regressions != 1 {
			t.Fatalf("target %d: want exactly one winner, got wins=%d regressions=%d", target, wins, regressions)
		}
		if v, _, _ := replicaA.CounterFor(ctx, key, scope); v != target {
			t.Fatalf("target %d: stored counter %d, want %d", target, v, target)
		}
	}
}

func TestPostgres_PingWritableDoesNotPersistProbe(t *testing.T) {
	dsn := testPGDSN(t)
	wm := newTestPG(t, dsn)
	ctx := context.Background()

	if err := wm.Ping(ctx); err != nil {
		t.Fatalf("Ping writable database: %v", err)
	}

	var payloadRows, counterRows int
	if err := wm.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM signer_watermark WHERE record_key = $1),
			(SELECT count(*) FROM signer_counter_watermark WHERE record_key = $1)
	`, readinessProbeRecordKey).Scan(&payloadRows, &counterRows); err != nil {
		t.Fatalf("count readiness probe rows: %v", err)
	}
	if payloadRows != 0 || counterRows != 0 {
		t.Fatalf(
			"readiness probe persisted rows: payload=%d counter=%d",
			payloadRows,
			counterRows,
		)
	}
}

func TestPostgres_PingRejectsReachableReadOnlyDatabase(t *testing.T) {
	dsn := testPGDSN(t)
	ctx := context.Background()

	writable := newTestPG(t, dsn)
	if err := writable.Ping(ctx); err != nil {
		t.Fatalf("Ping writable database: %v", err)
	}

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse Postgres DSN: %v", err)
	}
	poolConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET default_transaction_read_only = on`)
		return err
	}
	readOnlyPool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("create read-only Postgres pool: %v", err)
	}
	defer readOnlyPool.Close()

	if err := readOnlyPool.Ping(ctx); err != nil {
		t.Fatalf("read-only database should remain reachable: %v", err)
	}
	store := &PostgresWatermark{pool: readOnlyPool}
	if err := store.Ping(ctx); err == nil {
		t.Fatal("Ping succeeded for a reachable read-only database")
	}
}

func TestPostgres_PingRejectsMissingWritePermission(t *testing.T) {
	dsn := testPGDSN(t)
	ctx := context.Background()
	writable := newTestPG(t, dsn)
	key := randKey(t)
	roleName := fmt.Sprintf("bursa_readiness_%x", key[:8])
	quotedRole := pgx.Identifier{roleName}.Sanitize()

	if _, err := writable.pool.Exec(ctx, "CREATE ROLE "+quotedRole); err != nil {
		t.Fatalf("create restricted Postgres role: %v", err)
	}
	if _, err := writable.pool.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+quotedRole); err != nil {
		t.Fatalf("grant schema usage: %v", err)
	}
	if _, err := writable.pool.Exec(ctx, "GRANT SELECT ON signer_watermark TO "+quotedRole); err != nil {
		t.Fatalf("grant payload watermark read: %v", err)
	}
	if _, err := writable.pool.Exec(ctx, "GRANT SELECT ON signer_counter_watermark TO "+quotedRole); err != nil {
		t.Fatalf("grant counter watermark read: %v", err)
	}

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse Postgres DSN: %v", err)
	}
	poolConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+quotedRole)
		return err
	}
	restrictedPool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("create restricted Postgres pool: %v", err)
	}
	defer func() {
		restrictedPool.Close()
		if _, err := writable.pool.Exec(
			context.Background(),
			"DROP OWNED BY "+quotedRole,
		); err != nil {
			t.Errorf("drop restricted Postgres role privileges: %v", err)
		}
		if _, err := writable.pool.Exec(
			context.Background(),
			"DROP ROLE "+quotedRole,
		); err != nil {
			t.Errorf("drop restricted Postgres role: %v", err)
		}
	}()

	if err := restrictedPool.Ping(ctx); err != nil {
		t.Fatalf("restricted database should remain reachable: %v", err)
	}
	store := &PostgresWatermark{pool: restrictedPool}
	if err := store.Ping(ctx); err == nil {
		t.Fatal("Ping succeeded without watermark write permission")
	}
}

func TestPostgres_PingRejectsUnreachableDatabase(t *testing.T) {
	dsn := testPGDSN(t)
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse Postgres DSN: %v", err)
	}
	poolConfig.ConnConfig.Host = "127.0.0.1"
	poolConfig.ConnConfig.Port = 1
	poolConfig.ConnConfig.ConnectTimeout = 500 * time.Millisecond

	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("create unreachable Postgres pool: %v", err)
	}
	defer pool.Close()

	store := &PostgresWatermark{pool: pool}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := store.Ping(pingCtx); err == nil {
		t.Fatal("Ping succeeded for an unreachable database")
	}
}

func TestPostgres_PingHonorsCancellation(t *testing.T) {
	dsn := testPGDSN(t)
	wm := newTestPG(t, dsn)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := wm.Ping(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ping canceled context: want context.Canceled, got %v", err)
	}
}
