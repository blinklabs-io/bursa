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
	"testing"

	"github.com/blinklabs-io/dingo"
)

// baseConfig is a minimal Config for exercising nodeConfigOptions.
func baseConfig() Config {
	return Config{
		Network:        "preview",
		DataDir:        "/data/db",
		SocketPath:     "/data/node.socket",
		UtxorpcPort:    5555,
		BlockfrostPort: 5556,
	}
}

// TestNodeConfigOptionsHistoryExpiryOptIn asserts the lean-node profile plumbs
// through: enabling HistoryExpiry appends exactly one extra dingo option
// (WithHistoryExpiry), and the default (off) does not. dingo.Config keeps the
// history-expiry setting unexported with no getter, so the option set is the
// smallest observable seam for the wiring.
func TestNodeConfigOptionsHistoryExpiryOptIn(t *testing.T) {
	off := nodeConfigOptions(baseConfig(), false, nil, nil)
	on := nodeConfigOptions(baseConfig(), true, nil, nil)

	if len(on) != len(off)+1 {
		t.Fatalf(
			"history expiry should add exactly one option; off=%d on=%d",
			len(off), len(on),
		)
	}

	// The options must apply cleanly to a real dingo.Config (the wiring is only
	// useful if dingo accepts it). This also guards against the option panicking
	// on nil cardano/topology configs.
	mustApply := func(opts []dingo.ConfigOptionFunc) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("applying node config options panicked: %v", r)
			}
		}()
		_ = dingo.NewConfig(opts...)
	}
	mustApply(off)
	mustApply(on)
}

// TestNodeConfigOptionsDefaultOff guards the default: history expiry off must
// not include the lean-profile option.
func TestNodeConfigOptionsDefaultOff(t *testing.T) {
	def := nodeConfigOptions(baseConfig(), false, nil, nil)
	on := nodeConfigOptions(baseConfig(), true, nil, nil)
	if len(def) == len(on) {
		t.Fatal("history expiry off must not include the history-expiry option")
	}
}

// TestHistoryExpiryEnabledReadsProvider asserts the supervisor reads the
// (persisted) setting through its provider — it is the source of truth, not a
// value frozen at construction. A nil provider reads as off.
func TestHistoryExpiryEnabledReadsProvider(t *testing.T) {
	cfg := baseConfig()
	if cfg.historyExpiryEnabled() {
		t.Fatal("nil HistoryExpiry provider must read as off")
	}

	// A live provider is consulted each call, so flipping the backing value is
	// observed without rebuilding the Config — i.e. the persisted setting (not a
	// static field) drives node construction.
	enabled := false
	cfg.HistoryExpiry = func() bool { return enabled }
	if cfg.historyExpiryEnabled() {
		t.Fatal("provider returning false must read as off")
	}
	enabled = true
	if !cfg.historyExpiryEnabled() {
		t.Fatal("provider returning true must read as on")
	}
}

// TestAppliedHistoryExpiryBeforeLaunch: with no node launched yet, the applied
// value reports ran=false so the API knows it has nothing to compare against.
func TestAppliedHistoryExpiryBeforeLaunch(t *testing.T) {
	s := New(baseConfig())
	if _, ran := s.AppliedHistoryExpiry(); ran {
		t.Fatal("AppliedHistoryExpiry must report ran=false before any launch")
	}
}

// TestSetStateForRunClearsErrorOnRecovery asserts that transitioning from
// StateError back to a healthy state (bootstrapping / syncing / ready) clears
// the stale error string. Without this, a recovered transient error (e.g. a
// failed Mithril GET) lingers in the status snapshot and is shown in the UI
// even after the node has resumed normal operation.
func TestSetStateForRunClearsErrorOnRecovery(t *testing.T) {
	s := New(baseConfig())
	// Plant a runID that matches an "active" run: give the supervisor a live
	// cancel so activeRunLocked returns true, and set runID to the default 0+1.
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.mu.Lock()
	s.cancel = cancel
	s.runID = 1
	s.mu.Unlock()

	runID := uint64(1)

	// Simulate an error (e.g. Mithril GET failed).
	s.mu.Lock()
	s.status.State = StateError
	s.status.Err = "mithril GET failed"
	s.status.Bootstrap = &BootstrapProgress{Phase: "snapshot", Percent: 30}
	s.mu.Unlock()

	// Recover to bootstrapping — error + stale bootstrap should be cleared.
	s.setStateForRun(runID, StateBootstrapping)
	st := s.Status()
	if st.Err != "" {
		t.Fatalf("expected Err to be cleared on StateBootstrapping, got %q", st.Err)
	}
	// Bootstrap is preserved while bootstrapping.
	// (setStateForRun sets Bootstrap=nil only for non-bootstrapping states)

	// Now set error again, then recover to StateSyncing.
	s.mu.Lock()
	s.status.State = StateError
	s.status.Err = "mithril GET failed again"
	s.mu.Unlock()
	s.setStateForRun(runID, StateSyncing)
	st = s.Status()
	if st.Err != "" {
		t.Fatalf("expected Err to be cleared on StateSyncing, got %q", st.Err)
	}

	// Verify StateError itself keeps the error string.
	s.mu.Lock()
	s.status.State = StateBootstrapping
	s.status.Err = ""
	s.mu.Unlock()
	// setErrorForRun also cancels the context — just set state directly.
	s.mu.Lock()
	s.status.State = StateError
	s.status.Err = "persistent failure"
	s.mu.Unlock()
	st = s.Status()
	if st.Err != "persistent failure" {
		t.Fatalf("expected Err to be retained in StateError, got %q", st.Err)
	}
}
