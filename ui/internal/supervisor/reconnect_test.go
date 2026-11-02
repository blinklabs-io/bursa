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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/dingo"
)

type recoveryNodeFactory struct {
	starts int
	err    error
}

func (f *recoveryNodeFactory) New(_ dingo.Config) (NodeRunner, error) {
	f.starts++
	if f.err != nil {
		return nil, f.err
	}
	return fakeNodeRunner{}, nil
}

func TestRecoverReplacesOnlyNodeDataAndRestarts(t *testing.T) {
	appDir := t.TempDir()
	nodeDir := filepath.Join(appDir, "db")
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "metadata.sqlite"), []byte("chain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, bootstrapMarker), []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	retained := map[string]string{
		"vault.json":         "encrypted wallet and keys",
		"settings.json":      "settings",
		"contacts.json":      "contacts",
		"keystore.json":      "legacy keys",
		"logs/wallet.log":    "diagnostics",
		"nft-cache/item.bin": "cached media",
	}
	for name, contents := range retained {
		path := filepath.Join(appDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	factory := &recoveryNodeFactory{}
	s := New(Config{Network: "preview", DataDir: nodeDir, WalletDataDir: appDir})
	s.nodeFactory = factory
	s.bootstrapper = &fakeBootstrapper{}
	s.status.State = StateError
	t.Cleanup(s.Stop)

	if err := s.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if factory.starts != 1 {
		t.Fatalf("node starts = %d, want 1", factory.starts)
	}
	if _, err := os.Stat(filepath.Join(nodeDir, "metadata.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("node sync data still exists: %v", err)
	}
	for name, want := range retained {
		got, err := os.ReadFile(filepath.Join(appDir, name))
		if err != nil {
			t.Fatalf("read retained %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("retained %s = %q, want %q", name, got, want)
		}
	}
}

func TestRecoverKeepsErrorStateWhenRestartFails(t *testing.T) {
	appDir := t.TempDir()
	nodeDir := filepath.Join(appDir, "db")
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "metadata.sqlite"), []byte("chain"), 0o600); err != nil {
		t.Fatal(err)
	}
	factory := &recoveryNodeFactory{err: errors.New("start failed")}
	s := New(Config{Network: "preview", DataDir: nodeDir, WalletDataDir: appDir})
	s.nodeFactory = factory
	s.status.State = StateError

	err := s.Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start failed") {
		t.Fatalf("Recover = %v, want restart failure", err)
	}
	if factory.starts != 1 {
		t.Fatalf("node starts = %d, want 1", factory.starts)
	}
	if got := s.Status(); got.State != StateError || !strings.Contains(got.Err, "restart node") {
		t.Fatalf("status = %+v, want restart error", got)
	}
	entries, readErr := os.ReadDir(nodeDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("node directory has %d entries after clean restart failure", len(entries))
	}
}

func TestRecoverDoesNotRestartAfterCleanupFailure(t *testing.T) {
	appDir := t.TempDir()
	nodeDir := filepath.Join(appDir, "db")
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	factory := &recoveryNodeFactory{}
	s := New(Config{Network: "preview", DataDir: nodeDir, WalletDataDir: appDir})
	s.nodeFactory = factory
	s.status.State = StateError
	s.removeAll = func(string) error { return errors.New("cleanup failed") }

	err := s.Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("Recover = %v, want cleanup failure", err)
	}
	if factory.starts != 0 {
		t.Fatalf("node starts = %d, want 0", factory.starts)
	}
	if got := s.Status().State; got != StateError {
		t.Fatalf("state = %q, want error", got)
	}
}

func TestRecoverRejectsNodeDirectoryContainingWalletData(t *testing.T) {
	appDir := t.TempDir()
	factory := &recoveryNodeFactory{}
	s := New(Config{Network: "preview", DataDir: appDir, WalletDataDir: appDir})
	s.nodeFactory = factory
	s.status.State = StateError

	err := s.Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsafe node sync directory") {
		t.Fatalf("Recover = %v, want unsafe-directory error", err)
	}
	if factory.starts != 0 {
		t.Fatalf("node starts = %d, want 0", factory.starts)
	}
	if _, statErr := os.Stat(appDir); statErr != nil {
		t.Fatalf("wallet data directory was removed: %v", statErr)
	}
}

// fakeNodeRunner is a no-op NodeRunner for tests: Run blocks until ctx is
// cancelled (simulating a long-lived node) so Start can complete its goroutine
// launch without immediately returning an error.
type fakeNodeRunner struct{}

func (fakeNodeRunner) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// fakeNodeFactory creates fakeNodeRunners and never errors, allowing Start to
// succeed in tests without a real Dingo configuration.
type fakeNodeFactory struct{}

func (fakeNodeFactory) New(_ dingo.Config) (NodeRunner, error) { return fakeNodeRunner{}, nil }

type blockingNodeFactory struct {
	newRunner chan *blockingNodeRunner
}

func newBlockingNodeFactory() *blockingNodeFactory {
	return &blockingNodeFactory{newRunner: make(chan *blockingNodeRunner, 4)}
}

func (f *blockingNodeFactory) New(_ dingo.Config) (NodeRunner, error) {
	r := &blockingNodeRunner{
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
	f.newRunner <- r
	return r, nil
}

type blockingNodeRunner struct {
	canceled chan struct{}
	release  chan struct{}
}

func (r *blockingNodeRunner) Run(ctx context.Context) error {
	<-ctx.Done()
	close(r.canceled)
	<-r.release
	return ctx.Err()
}

// TestReconnectNoOpWhenNotRunning: Reconnect must be a safe no-op when the
// supervisor has not been started (no active run). It must not panic or return
// an error — the Android callback thread may call it before Start.
func TestReconnectNoOpWhenNotRunning(t *testing.T) {
	s := New(Config{Network: "preview", DataDir: t.TempDir()})
	if err := s.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect before Start = %v, want nil", err)
	}
	if got := s.Status().State; got != StateStopped {
		t.Fatalf("state after no-op Reconnect = %q, want stopped", got)
	}
}

// TestReconnectNoOpAfterStop: Reconnect is a no-op after an explicit Stop.
func TestReconnectNoOpAfterStop(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.setState(StateStarting)
	s.Stop()
	if err := s.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect after Stop = %v, want nil", err)
	}
	if got := s.Status().State; got != StateStopped {
		t.Fatalf("state after no-op Reconnect = %q, want stopped", got)
	}
}

// TestReconnectWhileRunningIncreasesRunID: Reconnect while the supervisor is
// running must perform a Stop-then-relaunch cycle, producing a strictly
// greater runID (the observable signal that the node restarted) while keeping
// the DataDir (no re-bootstrap).
func TestReconnectWhileRunningIncreasesRunID(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.nodeFactory = fakeNodeFactory{}
	s.setState(StateStarting)
	t.Cleanup(s.Stop)
	beforeRunID := s.runID

	// Reconnect replaces the current run with a new one.
	if err := s.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect while running = %v, want nil", err)
	}

	afterRunID := s.runID
	if afterRunID <= beforeRunID {
		t.Fatalf("runID did not increase: before=%d after=%d", beforeRunID, afterRunID)
	}
}

func TestReconnectWaitsForPreviousRunToExit(t *testing.T) {
	factory := newBlockingNodeFactory()
	s := New(Config{Network: "preview", DataDir: t.TempDir()})
	s.bootstrapper = &fakeBootstrapper{}
	s.nodeFactory = factory
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start = %v", err)
	}
	first := waitForRunner(t, factory.newRunner)

	reconnectErr := make(chan error, 1)
	go func() {
		reconnectErr <- s.Reconnect(context.Background())
	}()

	waitForClosed(t, first.canceled, "first runner cancellation")
	select {
	case <-factory.newRunner:
		t.Fatal("Reconnect started a replacement node before the previous Run exited")
	case <-time.After(50 * time.Millisecond):
	}

	close(first.release)
	second := waitForRunner(t, factory.newRunner)
	select {
	case err := <-reconnectErr:
		if err != nil {
			t.Fatalf("Reconnect = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Reconnect did not return after the previous Run exited")
	}

	stopDone := make(chan struct{})
	go func() {
		s.Stop()
		close(stopDone)
	}()
	waitForClosed(t, second.canceled, "second runner cancellation")
	close(second.release)
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after the second Run exited")
	}
}

func TestReconnectReturnsContextErrorIfCanceledBeforeRestart(t *testing.T) {
	factory := newBlockingNodeFactory()
	s := New(Config{Network: "preview", DataDir: t.TempDir()})
	s.bootstrapper = &fakeBootstrapper{}
	s.nodeFactory = factory
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start = %v", err)
	}
	first := waitForRunner(t, factory.newRunner)

	ctx, cancel := context.WithCancel(context.Background())
	reconnectErr := make(chan error, 1)
	go func() {
		reconnectErr <- s.Reconnect(ctx)
	}()

	waitForClosed(t, first.canceled, "first runner cancellation")
	cancel()
	close(first.release)

	select {
	case err := <-reconnectErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Reconnect = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Reconnect did not return after the previous Run exited")
	}

	select {
	case <-factory.newRunner:
		t.Fatal("Reconnect started a replacement node with a canceled context")
	default:
	}
	if got := s.Status().State; got != StateStopped {
		t.Fatalf("state after canceled Reconnect = %q, want stopped", got)
	}
}

// TestReconnectDoesNotReBootstrap: Reconnect must not trigger a Mithril
// bootstrap. Even when MithrilEnabled is true, if shouldBootstrap returns false
// (because the DataDir already has the completion marker), the relaunch must
// skip the bootstrap path entirely — no re-download, no data loss.
func TestReconnectDoesNotReBootstrap(t *testing.T) {
	dir := t.TempDir()
	// Write the bootstrap-done marker so shouldBootstrap returns false.
	if err := markBootstrapDone(dir); err != nil {
		t.Fatalf("markBootstrapDone: %v", err)
	}

	fb := &fakeBootstrapper{}
	s := New(Config{
		Network:        "preview",
		DataDir:        dir,
		MithrilEnabled: true,
	})
	s.bootstrapper = fb
	s.nodeFactory = fakeNodeFactory{}
	// Simulate an already-running node (reuse newTestSupervisor's pattern).
	s.runID = 1
	s.cancel = func() {}
	s.status.State = StateStarting
	t.Cleanup(s.Stop)

	if err := s.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect = %v, want nil", err)
	}

	if fb.called {
		t.Fatal("Reconnect must not trigger a bootstrap (marker is present)")
	}
	if !bootstrapDone(dir) {
		t.Fatal("bootstrap marker must be preserved after Reconnect")
	}
}

// TestReconnectConcurrentStopWins: concurrent calls to Reconnect and Stop from
// different goroutines must not panic/deadlock, and once the explicit Stop has
// completed no racing reconnect may resurrect the node afterward.
func TestReconnectConcurrentStopWins(t *testing.T) {
	s := newTestSupervisor(t, &fakeBootstrapper{})
	s.nodeFactory = fakeNodeFactory{}
	s.setState(StateStarting)

	var wg sync.WaitGroup
	const goroutines = 10
	ctx := context.Background()
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Reconnect(ctx)
		}()
	}
	// Also race Stop with the reconnects.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.Stop()
	}()
	wg.Wait()
	if got := s.Status().State; got != StateStopped {
		t.Fatalf("state after concurrent Reconnect/Stop = %q, want stopped", got)
	}
}

func waitForRunner(t *testing.T, ch <-chan *blockingNodeRunner) *blockingNodeRunner {
	t.Helper()
	select {
	case runner := <-ch:
		return runner
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for node runner")
		return nil
	}
}

func waitForClosed(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}
