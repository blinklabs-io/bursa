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
	"os"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/dingo/mithril"
)

func TestSyncConfigForMapsFields(t *testing.T) {
	sc := syncConfigFor(BootstrapParams{Network: "preview", DataDir: "/data/db"}, nil)
	if sc.Network != "preview" || sc.DataDir != "/data/db" {
		t.Fatalf("network/datadir: %+v", sc)
	}
	if sc.StorageMode != "api" ||
		sc.StoragePlugins.Blob.Provider != "badger" ||
		sc.StoragePlugins.Metadata.Provider != "sqlite" {
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
	s.bootstrapThenLaunch(context.Background(), s.runID, func() error { launched = true; return nil }, func() {})

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
	s.bootstrapThenLaunch(context.Background(), s.runID, func() error { launched = true; return nil }, func() {})

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
	s.bootstrapThenLaunch(ctx, s.runID, func() error { launched = true; return nil }, func() {})

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
	}, func() {})

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

// dingo runs the ledger import and the immutable copy CONCURRENTLY (one
// errgroup, two goroutines, mithril/sync.go), and both report through the same
// progress callback. Keeping only the newest report makes /status alternate
// between two unrelated percentages — a measured preview bootstrap reported
// immutable_copy 75.1%, then ledger_import 52.3%, then immutable_copy 79.0%.
// Retaining each phase's own latest progress is what lets a reader see two
// things running rather than one number jumping around.
func TestOnProgressRetainsConcurrentPhases(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "immutable_copy", Percent: 75.1})
	s.onProgress(BootstrapProgress{Phase: "ledger_import", Percent: 52.3})
	s.onProgress(BootstrapProgress{Phase: "immutable_copy", Percent: 79})

	phases := s.Status().BootstrapPhases
	if len(phases) != 2 {
		t.Fatalf("want both concurrent phases retained, got %+v", phases)
	}
	// First-seen order, so a phase does not move under the reader.
	if phases[0].Phase != "immutable_copy" || phases[0].Percent != 79 {
		t.Errorf("immutable_copy should hold its own latest percent: %+v", phases[0])
	}
	if phases[1].Phase != "ledger_import" || phases[1].Percent != 52.3 {
		t.Errorf("ledger_import should hold its own latest percent: %+v", phases[1])
	}
}

// The phase-end edge carries no measurements (dingo emits a bare
// {Phase, Active: false}), so applying it verbatim would blank a phase that
// just finished — reporting 0% for completed work.
func TestOnProgressEndEdgeCompletesRatherThanBlanks(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "immutable_copy", Percent: 99.8, Count: 3634100})
	s.onProgress(BootstrapProgress{Phase: "immutable_copy", Done: true})

	phases := s.Status().BootstrapPhases
	if len(phases) != 1 {
		t.Fatalf("want one phase, got %+v", phases)
	}
	if !phases[0].Done {
		t.Error("the end edge should mark the phase done")
	}
	if phases[0].Percent != 99.8 {
		t.Errorf("the end edge must not overwrite the measured percent: %v", phases[0].Percent)
	}
	if phases[0].Count != 3634100 {
		t.Errorf("the end edge must not discard what the phase measured: %+v", phases[0])
	}
	// The headline stays on real progress rather than the empty edge report.
	if got := s.Status().Bootstrap; got == nil || got.Percent != 99.8 {
		t.Errorf("Status.Bootstrap blanked by the end edge: %+v", got)
	}
}

// Status is copied out by value; a retained slice shared with the caller would
// let a reader observe a phase mutating mid-render.
func TestStatusCopiesPhases(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "immutable_copy", Percent: 10})

	snapshot := s.Status()
	s.onProgress(BootstrapProgress{Phase: "immutable_copy", Percent: 20})

	if snapshot.BootstrapPhases[0].Percent != 10 {
		t.Fatal("Status() handed out the live slice: an earlier snapshot changed under the caller")
	}
}

func TestSetStateClearsBootstrapPhases(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "immutable_copy", Percent: 10})
	s.setState(StateStarting)
	if s.Status().BootstrapPhases != nil {
		t.Fatal("leaving StateBootstrapping should clear the retained phases")
	}
}

// Active marks a phase's begin/end edge. Dropping it entirely (as this
// conversion once did) loses the only signal that a phase finished, leaving the
// end edge indistinguishable from a 0% report.
func TestToBootstrapProgressCarriesPhaseEnd(t *testing.T) {
	if got := toBootstrapProgress(mithril.SyncProgress{
		Phase:  mithril.PhaseImmutableCopy,
		Active: false,
	}); !got.Done {
		t.Errorf("phase-end edge should convert to Done: %+v", got)
	}
	if got := toBootstrapProgress(mithril.SyncProgress{
		Phase:   mithril.PhaseImmutableCopy,
		Active:  true,
		Percent: 12,
	}); got.Done {
		t.Errorf("a mid-phase tick is not done: %+v", got)
	}
}

// The download phase is itself two downloads running in parallel: the immutable
// archives (14.8 GB on preview) and the ancillary ledger state. dingo fetches
// them concurrently and reports both through one callback
// (mithril/bootstrap_v2.go, "Steps 4+5 ... in parallel"), labelling each report
// with the artifact it describes — but drops that label when it flattens into
// mithril.SyncProgress, so what reaches us is one phase carrying two
// interleaved series over two different totals. Keyed on the phase alone they
// collapse into a row whose percent AND size flip between two downloads.
func TestOnProgressSeparatesConcurrentDownloads(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{
		Phase: "bootstrap", Percent: 75,
		BytesDownloaded: 11086556385, TotalBytes: 14779773204,
	})
	s.onProgress(BootstrapProgress{
		Phase: "bootstrap", Percent: 12,
		BytesDownloaded: 30000000, TotalBytes: 250000000,
	})
	s.onProgress(BootstrapProgress{
		Phase: "bootstrap", Percent: 78,
		BytesDownloaded: 11530022099, TotalBytes: 14779773204,
	})

	phases := s.Status().BootstrapPhases
	if len(phases) != 2 {
		t.Fatalf("want one row per download, got %+v", phases)
	}
	if phases[0].TotalBytes != 14779773204 || phases[0].Percent != 78 {
		t.Errorf("the immutable download should keep its own progress: %+v", phases[0])
	}
	if phases[1].TotalBytes != 250000000 || phases[1].Percent != 12 {
		t.Errorf("the ancillary download should keep its own progress: %+v", phases[1])
	}
}

// The phase ends once, for the phase as a whole — dingo emits no per-download
// end edge — so it has to finish every download it covers.
func TestPhaseEndCompletesEveryDownload(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "bootstrap", Percent: 99.8, TotalBytes: 14779773204})
	s.onProgress(BootstrapProgress{Phase: "bootstrap", Percent: 100, TotalBytes: 250000000})
	s.onProgress(BootstrapProgress{Phase: "bootstrap", Done: true})

	phases := s.Status().BootstrapPhases
	if len(phases) != 2 {
		t.Fatalf("the end edge should not add a row of its own: %+v", phases)
	}
	for _, p := range phases {
		if !p.Done {
			t.Errorf("the phase ended, so this download is not still running: %+v", p)
		}
	}
	if phases[0].Percent != 99.8 || phases[1].Percent != 100 {
		t.Errorf("each download should keep the progress it measured: %+v", phases)
	}
	// Each row keeps the size it was measuring, so neither is mistaken for the
	// other after the fact.
	if phases[0].TotalBytes == phases[1].TotalBytes {
		t.Error("the end edge collapsed two different downloads into one size")
	}
}

// A phase opens with a bare "started" report carrying no measurements, and only
// then do its real reports arrive. Observed live on preview, the download phase
// held four rows: the empty opener, plus the three downloads it actually runs
// (digest list 3.4 MB, ancillary ledger state 244 MB, immutable archives
// 13.8 GB). The opener has nothing to show and never gains anything, so the
// first measured report for the phase takes its place.
func TestPhaseOpenerIsReplacedByRealProgress(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "bootstrap"})
	s.onProgress(BootstrapProgress{
		Phase: "bootstrap", Percent: 100,
		BytesDownloaded: 3525541, TotalBytes: 3525541,
	})
	s.onProgress(BootstrapProgress{
		Phase: "bootstrap", Percent: 29.1,
		BytesDownloaded: 74397448, TotalBytes: 255611612,
	})
	s.onProgress(BootstrapProgress{
		Phase: "bootstrap", Percent: 1.13,
		BytesDownloaded: 166499926, TotalBytes: 14780304000,
	})

	phases := s.Status().BootstrapPhases
	if len(phases) != 3 {
		t.Fatalf("want one row per download and no empty opener, got %+v", phases)
	}
	for _, p := range phases {
		if p.TotalBytes == 0 {
			t.Errorf("an empty row survived: %+v", p)
		}
	}
}

// Until the first real report arrives the opener is all there is, and it does
// say something: this phase is running.
func TestPhaseOpenerStandsUntilMeasured(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "bootstrap"})

	phases := s.Status().BootstrapPhases
	if len(phases) != 1 || phases[0].Phase != "bootstrap" {
		t.Fatalf("the phase should show as running: %+v", phases)
	}
}

// A phase that measures something other than bytes (the ledger import reports a
// count and a percent) still replaces its own opener rather than sitting beside
// it.
func TestNonByteProgressReplacesOpener(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{Phase: "ledger_import"})
	s.onProgress(BootstrapProgress{Phase: "ledger_import", Percent: 47.1, Count: 1490000})

	phases := s.Status().BootstrapPhases
	if len(phases) != 1 || phases[0].Percent != 47.1 {
		t.Fatalf("want the opener replaced by the measured report, got %+v", phases)
	}
}

// The end edge is a defer: dingo emits it whether the phase succeeded or was
// torn down by an error elsewhere. Observed live — a bootstrap that failed in
// the ledger import left the immutable copy reporting "done", having copied 50
// blocks of 122 million. Reporting 100% there states something the node never
// said. The end edge marks work finished; what it got through is whatever it
// last measured.
func TestPhaseEndKeepsTheProgressItActuallyMade(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateBootstrapping)
	s.onProgress(BootstrapProgress{
		Phase: "immutable_copy", Percent: 0.04, Count: 50,
		CurrentSlot: 980, TipSlot: 122601558,
	})
	s.onProgress(BootstrapProgress{Phase: "immutable_copy", Done: true})

	phases := s.Status().BootstrapPhases
	if len(phases) != 1 {
		t.Fatalf("want one row, got %+v", phases)
	}
	if !phases[0].Done {
		t.Error("the end edge should mark the phase finished")
	}
	if phases[0].Percent != 0.04 {
		t.Errorf("an aborted phase must not claim completion: %+v", phases[0])
	}
	if phases[0].Count != 50 {
		t.Errorf("the end edge must not discard what the phase measured: %+v", phases[0])
	}
}
