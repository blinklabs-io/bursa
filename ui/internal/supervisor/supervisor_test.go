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
	"os"
	"path/filepath"
	"testing"
	"time"

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

type blockingBootstrapper struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingBootstrapper) Bootstrap(ctx context.Context, p BootstrapParams) error {
	if err := os.MkdirAll(p.DataDir, 0o700); err != nil {
		return err
	}
	close(b.started)
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type nodeRunnerFunc func(context.Context) error

func (f nodeRunnerFunc) Run(ctx context.Context) error { return f(ctx) }

func TestStartReadsHistoryExpiryAtDeferredBootstrapLaunch(t *testing.T) {
	enabled := false
	cfg := baseConfig()
	dir := t.TempDir()
	cfg.DataDir = filepath.Join(dir, "db")
	cfg.SocketPath = filepath.Join(dir, "node.socket")
	cfg.MithrilEnabled = true
	cfg.HistoryExpiry = func() bool { return enabled }

	s := New(cfg)
	fb := &blockingBootstrapper{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	s.bootstrapper = fb
	nodeStarted := make(chan struct{})
	s.newNode = func(dingo.Config) (nodeRunner, error) {
		return nodeRunnerFunc(func(ctx context.Context) error {
			close(nodeStarted)
			<-ctx.Done()
			return ctx.Err()
		}), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	select {
	case <-fb.started:
	case <-time.After(time.Second):
		t.Fatal("bootstrap did not start")
	}

	enabled = true
	close(fb.release)

	select {
	case <-nodeStarted:
	case <-time.After(time.Second):
		t.Fatal("node was not launched after bootstrap")
	}
	applied, ran := s.AppliedHistoryExpiry()
	if !ran || !applied {
		t.Fatalf("AppliedHistoryExpiry = (%v, %v), want (true, true)", applied, ran)
	}
}
