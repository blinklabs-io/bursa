// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package supervisor

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/dingo/mithril"
)

func TestSyncConfigForMapsFields(t *testing.T) {
	sc := syncConfigFor(BootstrapParams{Network: "preview", DataDir: "/data/db"}, nil)
	if sc.Network != "preview" || sc.DataDir != "/data/db" {
		t.Fatalf("network/datadir: %+v", sc)
	}
	if sc.StorageMode != "api" || sc.BlobPlugin != "badger" || sc.MetadataPlugin != "sqlite" {
		t.Fatalf("storage/plugins: %+v", sc)
	}
	if !sc.VerifyCertChain || !sc.CleanupAfterLoad {
		t.Fatalf("verify/cleanup should be true: %+v", sc)
	}
	// dingo's API-mode backfill rejects a zero batch size, so we must set one.
	if sc.BackfillBatchSize <= 0 {
		t.Fatalf("BackfillBatchSize must be positive, got %d", sc.BackfillBatchSize)
	}
}

func TestSyncConfigForWiresProgress(t *testing.T) {
	var got BootstrapProgress
	sc := syncConfigFor(BootstrapParams{OnProgress: func(b BootstrapProgress) { got = b }}, nil)
	sc.OnProgress(mithril.SyncProgress{Phase: mithril.PhaseLedgerImport, Percent: 50, BytesDownloaded: 3, TotalBytes: 6, BytesPerSecond: 1.5})
	if got.Phase != "ledger_import" || got.Percent != 50 || got.BytesDownloaded != 3 || got.TotalBytes != 6 || got.BytesPerSecond != 1.5 {
		t.Fatalf("progress not mapped: %+v", got)
	}

	// The block-replay positional fields (slot/count/description) must survive
	// too — they're what the sync view renders to show "where it is".
	sc.OnProgress(mithril.SyncProgress{
		Phase:       mithril.PhaseBackfill,
		Percent:     71,
		CurrentSlot: 97740,
		TipSlot:     132000,
		Count:       18432,
		Total:       25900,
		Description: "Conway",
	})
	if got.CurrentSlot != 97740 || got.TipSlot != 132000 || got.Count != 18432 || got.Total != 25900 || got.Description != "Conway" {
		t.Fatalf("positional progress not mapped: %+v", got)
	}

	// A nil OnProgress must not panic.
	syncConfigFor(BootstrapParams{}, nil).OnProgress(mithril.SyncProgress{})
}

func TestBootstrapMarkerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if bootstrapDone(dir) {
		t.Fatal("marker should be absent initially")
	}
	if err := markBootstrapDone(dir); err != nil {
		t.Fatalf("markBootstrapDone: %v", err)
	}
	if !bootstrapDone(dir) {
		t.Fatal("marker should be present after marking")
	}
}

// TestBootstrapDoneUnreadableMarker: when the marker cannot be inspected (a
// stat error other than not-exist), bootstrapDone must report true so we never
// re-import a snapshot over a DB we cannot see into; the node launch surfaces
// the real error instead.
func TestBootstrapDoneUnreadableMarker(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission errors do not apply")
	}
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "db")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	if !bootstrapDone(dataDir) {
		t.Fatal("an unreadable marker must read as bootstrapped (no re-import)")
	}
}

func TestShouldBootstrap(t *testing.T) {
	dir := t.TempDir()
	if !shouldBootstrap(true, dir) {
		t.Fatal("enabled + no marker → should bootstrap")
	}
	if shouldBootstrap(false, dir) {
		t.Fatal("disabled → should not bootstrap")
	}
	_ = markBootstrapDone(dir)
	if shouldBootstrap(true, dir) {
		t.Fatal("enabled + marker present → should not bootstrap")
	}
}

// fakeBootstrapper drives progress then returns err.
type fakeBootstrapper struct {
	err      error
	progress []BootstrapProgress
	called   bool
}

func (f *fakeBootstrapper) Bootstrap(_ context.Context, p BootstrapParams) error {
	f.called = true
	for _, bp := range f.progress {
		if p.OnProgress != nil {
			p.OnProgress(bp)
		}
	}
	return f.err
}

func newTestSupervisor(t *testing.T, b Bootstrapper) *Supervisor {
	t.Helper()
	s := New(Config{Network: "preview", DataDir: t.TempDir()})
	s.bootstrapper = b
	s.bootstrapBackoff = zeroBackoff // instant retries in tests
	s.runID = 1
	s.cancel = func() {} // represent an active run so setState/setError apply
	return s
}

func TestOnProgressUpdatesStatus(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "backfill", Percent: 12})
	got := s.Status().Bootstrap
	if got == nil || got.Phase != "backfill" || got.Percent != 12 {
		t.Fatalf("Status.Bootstrap not updated: %+v", got)
	}
}

func TestSetStateClearsBootstrap(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "backfill"})
	s.setState(StateStarting)
	if s.Status().Bootstrap != nil {
		t.Fatal("leaving StateBootstrapping should clear Status.Bootstrap")
	}
}

func TestBootstrapThenLaunchSuccess(t *testing.T) {
	fb := &fakeBootstrapper{progress: []BootstrapProgress{{Phase: "bootstrap", Percent: 100}}}
	s := newTestSupervisor(t, fb)
	launched := false
	s.setState(StateBootstrapping)
	s.bootstrapThenLaunch(context.Background(), s.runID, func() error { launched = true; return nil })

	if !fb.called {
		t.Fatal("bootstrapper not invoked")
	}
	if !launched {
		t.Fatal("launch not called after successful bootstrap")
	}
	if !bootstrapDone(s.cfg.DataDir) {
		t.Fatal("completion marker not written")
	}
	// State transitions are driven by the real launch (setState(StateStarting));
	// the fake launch here doesn't transition, so that path is covered by
	// TestSetStateClearsBootstrap instead.
}

func TestBootstrapThenLaunchFailureSetsError(t *testing.T) {
	fb := &fakeBootstrapper{
		progress: []BootstrapProgress{{Phase: "ledger_import", Percent: 40}},
		err:      errors.New("aggregator unreachable"),
	}
	s := newTestSupervisor(t, fb)
	launched := false
	s.setState(StateBootstrapping)
	s.bootstrapThenLaunch(context.Background(), s.runID, func() error { launched = true; return nil })

	if launched {
		t.Fatal("launch must NOT be called when bootstrap fails")
	}
	st := s.Status()
	if st.State != StateError {
		t.Fatalf("state = %q, want error", st.State)
	}
	// Progress is intentionally retained on error for diagnostics.
	if st.Bootstrap == nil || st.Bootstrap.Phase != "ledger_import" {
		t.Fatalf("bootstrap progress should be retained on error, got %+v", st.Bootstrap)
	}
	if bootstrapDone(s.cfg.DataDir) {
		t.Fatal("marker must not be written on failure")
	}
}

// TestBootstrapCancellationIsNotError: a bootstrap aborted by context
// cancellation is an orderly shutdown, not a failure — it must not flip the
// supervisor to StateError (mirrors the node.Run guard).
func TestBootstrapCancellationIsNotError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fb := &fakeBootstrapper{err: context.Canceled}
	s := newTestSupervisor(t, fb)
	s.setState(StateBootstrapping)
	launched := false
	s.bootstrapThenLaunch(ctx, s.runID, func() error { launched = true; return nil })

	if launched {
		t.Fatal("launch must NOT be called when bootstrap is cancelled")
	}
	if got := s.Status().State; got == StateError {
		t.Fatalf("cancellation flipped state to error: %s", s.Status().Err)
	}
	if bootstrapDone(s.cfg.DataDir) {
		t.Fatal("marker must not be written on cancellation")
	}
}

// TestBootstrapPostSuccessCancellationStopsBeforeLaunch covers cancellation
// after Bootstrap returns nil but before post-bootstrap work. That late path
// must not mark the supervisor errored or launch a node for the canceled run.
func TestBootstrapPostSuccessCancellationStopsBeforeLaunch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	launched := false
	s.bootstrapThenLaunch(ctx, s.runID, func() error {
		launched = true
		return errors.New("late launch failure")
	})

	if launched {
		t.Fatal("launch must NOT be called after cancellation")
	}
	if got := s.Status().State; got == StateError {
		t.Fatalf("post-bootstrap cancellation flipped state to error: %s", s.Status().Err)
	}
	if bootstrapDone(s.cfg.DataDir) {
		t.Fatal("marker must not be written after cancellation")
	}
}

// TestOnProgressIgnoredAfterStop guards the teardown invariant for progress
// callbacks: a late OnProgress from an in-flight bootstrap must not write
// bootstrap data into a stopped snapshot.
func TestOnProgressIgnoredAfterStop(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.Stop()
	s.onProgress(BootstrapProgress{Phase: "backfill", Percent: 12})
	if s.Status().Bootstrap != nil {
		t.Fatal("onProgress after Stop must be a no-op")
	}
}

func TestOnProgressIgnoredOutsideBootstrapping(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateStarting)
	s.onProgress(BootstrapProgress{Phase: "backfill", Percent: 12})
	if s.Status().Bootstrap != nil {
		t.Fatal("onProgress outside bootstrapping must be a no-op")
	}
}

func TestStaleOnProgressIgnoredAfterRestart(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	oldRunID := s.runID
	s.runID++
	s.setState(StateBootstrapping)
	s.onProgressForRun(oldRunID, BootstrapProgress{Phase: "old", Percent: 12})
	if s.Status().Bootstrap != nil {
		t.Fatal("stale onProgress after restart must be a no-op")
	}

	s.onProgress(BootstrapProgress{Phase: "new", Percent: 34})
	got := s.Status().Bootstrap
	if got == nil || got.Phase != "new" || got.Percent != 34 {
		t.Fatalf("current run progress not recorded: %+v", got)
	}
}

// TestSetStateIgnoredAfterStop guards the teardown invariant: once Stop clears
// cancel, a late goroutine's setState must not resurrect the supervisor.
func TestSetStateIgnoredAfterStop(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.Stop() // → StateStopped, clears cancel
	s.setState(StateStarting)
	if got := s.Status().State; got != StateStopped {
		t.Fatalf("setState after Stop must be a no-op; state = %q, want stopped", got)
	}
}

// TestSetErrorIgnoredAfterStop guards the same invariant for setError: a late
// failure must not overwrite the stopped state.
func TestSetErrorIgnoredAfterStop(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.Stop()
	s.setError(errors.New("late failure"))
	if got := s.Status().State; got != StateStopped {
		t.Fatalf("setError after Stop must be a no-op; state = %q, want stopped", got)
	}
}

// --- Retry tests -----------------------------------------------------------

// countingBootstrapper fails the first `failCount` calls then succeeds.
type countingBootstrapper struct {
	failCount int
	calls     int
	failErr   error
}

func (c *countingBootstrapper) Bootstrap(_ context.Context, _ BootstrapParams) error {
	c.calls++
	if c.calls <= c.failCount {
		return c.failErr
	}
	return nil
}

// alwaysFailingBootstrapper always returns an error.
type alwaysFailingBootstrapper struct {
	calls int
	err   error
}

func (a *alwaysFailingBootstrapper) Bootstrap(_ context.Context, _ BootstrapParams) error {
	a.calls++
	return a.err
}

// zeroBackoff is a 0-duration initial backoff for tests: retries are
// instantaneous, so the test suite runs in milliseconds rather than minutes.
const zeroBackoff = time.Duration(0)

// TestBootstrapWithRetrySucceedsAfterTransientFailures verifies that
// bootstrapWithRetry retries and eventually succeeds when the bootstrapper
// fails fewer times than maxAttempts.
func TestBootstrapWithRetrySucceedsAfterTransientFailures(t *testing.T) {
	cb := &countingBootstrapper{failCount: 3, failErr: errors.New("transient aggregator error")}
	// With maxAttempts=5 and failCount=3, attempt 4 should succeed.
	err := bootstrapWithRetry(context.Background(), cb, BootstrapParams{}, slog.Default(), 5, zeroBackoff)
	if err != nil {
		t.Fatalf("expected success after transient failures, got: %v", err)
	}
	if cb.calls != 4 {
		t.Fatalf("expected 4 calls (3 failures + 1 success), got %d", cb.calls)
	}
}

// TestBootstrapWithRetryExhaustsAndErrors verifies that bootstrapWithRetry
// returns a non-nil error after exhausting all maxAttempts.
func TestBootstrapWithRetryExhaustsAndErrors(t *testing.T) {
	af := &alwaysFailingBootstrapper{err: errors.New("persistent network error")}
	err := bootstrapWithRetry(context.Background(), af, BootstrapParams{}, slog.Default(), 5, zeroBackoff)
	if err == nil {
		t.Fatal("expected error after exhausting all attempts, got nil")
	}
	if af.calls != 5 {
		t.Fatalf("expected exactly 5 calls, got %d", af.calls)
	}
}

// TestBootstrapWithRetryCancellationStopsImmediately verifies that
// bootstrapWithRetry respects context cancellation and does not retry.
func TestBootstrapWithRetryCancellationStopsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	af := &alwaysFailingBootstrapper{err: context.Canceled}
	err := bootstrapWithRetry(ctx, af, BootstrapParams{}, slog.Default(), 5, zeroBackoff)
	if err == nil {
		t.Fatal("expected error on cancellation, got nil")
	}
	// With a pre-cancelled context, the loop guard (ctx.Err() != nil) fires at
	// the top of the first iteration and returns before calling Bootstrap — so
	// exactly 0 attempts are made. No retries are attempted.
	if af.calls != 0 {
		t.Fatalf("expected 0 calls on pre-cancelled context, got %d", af.calls)
	}
}

// newTestSupervisorFast creates a test supervisor with zero back-off so that
// retry tests complete instantly rather than waiting on real sleep intervals.
func newTestSupervisorFast(t *testing.T, b Bootstrapper) *Supervisor {
	t.Helper()
	s := newTestSupervisor(t, b)
	s.bootstrapBackoff = zeroBackoff
	return s
}

// TestBootstrapThenLaunchWithRetriesSucceeds verifies the full
// bootstrapThenLaunch path retries on transient failures and eventually
// reaches the launch function.
func TestBootstrapThenLaunchWithRetriesSucceeds(t *testing.T) {
	// Fail 2 times, succeed on the 3rd attempt.
	cb := &countingBootstrapper{failCount: 2, failErr: errors.New("flaky network")}
	s := newTestSupervisorFast(t, cb)
	s.setState(StateBootstrapping)

	launched := false
	s.bootstrapThenLaunch(context.Background(), s.runID, func() error {
		launched = true
		return nil
	})

	if !launched {
		t.Fatal("launch must be called after retries succeed")
	}
	if cb.calls != 3 {
		t.Fatalf("expected 3 bootstrap calls (2 failures + 1 success), got %d", cb.calls)
	}
	if s.Status().State == StateError {
		t.Fatalf("state must not be error after successful retry, got %q", s.Status().State)
	}
}

// TestBootstrapThenLaunchWithRetryExhaustsAndSetsError verifies that
// bootstrapThenLaunch sets StateError after all attempts are exhausted.
func TestBootstrapThenLaunchWithRetryExhaustsAndSetsError(t *testing.T) {
	af := &alwaysFailingBootstrapper{err: errors.New("persistent failure")}
	s := newTestSupervisorFast(t, af)
	s.setState(StateBootstrapping)

	launched := false
	s.bootstrapThenLaunch(context.Background(), s.runID, func() error {
		launched = true
		return nil
	})

	if launched {
		t.Fatal("launch must NOT be called when all attempts fail")
	}
	if st := s.Status().State; st != StateError {
		t.Fatalf("state must be error after exhausting retries, got %q", st)
	}
	if af.calls != bootstrapMaxAttempts {
		t.Fatalf("expected %d total calls, got %d", bootstrapMaxAttempts, af.calls)
	}
}
