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
//
//go:build integration

package supervisor

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestSupervisorBootsPreview boots a real preview node and asserts it leaves
// StateStarting (i.e. begins syncing). It needs outbound Dingo P2P and time.
func TestSupervisorBootsPreview(t *testing.T) {
	dir := t.TempDir()
	s := New(Config{
		Network:        "preview",
		DataDir:        filepath.Join(dir, "db"),
		SocketPath:     filepath.Join(dir, "node.socket"),
		UtxorpcPort:    0, // disable for this test
		BlockfrostPort: 0, // disable: the test checks state transitions, not the HTTP surface
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		st := s.Status()
		if st.State == StateError {
			t.Fatalf("node errored: %s", st.Err)
		}
		if st.State == StateSyncing || st.State == StateReady {
			return // success: it is making progress
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("node did not reach syncing within deadline; last state=%s", s.Status().State)
}

func TestMithrilBootstrapLivePreview(t *testing.T) {
	dir := t.TempDir()
	sup := New(Config{
		Network:        "preview",
		DataDir:        filepath.Join(dir, "db"),
		SocketPath:     filepath.Join(dir, "node.socket"),
		UtxorpcPort:    0,
		BlockfrostPort: 0, // disabled; this test checks bootstrap→serving transitions, not the HTTP surface
		MithrilEnabled: true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop()

	// Expect a bootstrapping phase first, with progress, then a servable node.
	sawBootstrapping := false
	deadline := time.Now().Add(20 * time.Minute) // a preview snapshot import can take a while
	// Clamp to the harness deadline (default -timeout is 10m) so the test fails
	// its own check with a real message instead of the binary's timeout panic.
	if d, ok := t.Deadline(); ok && d.Before(deadline) {
		deadline = d.Add(-15 * time.Second)
	}
	for {
		st := sup.Status()
		switch st.State {
		case StateBootstrapping:
			sawBootstrapping = true
			if st.Bootstrap != nil {
				t.Logf("bootstrap: phase=%s percent=%.1f", st.Bootstrap.Phase, st.Bootstrap.Percent)
			}
		case StateSyncing, StateReady:
			// The DB dir is a fresh TempDir and Start sets StateBootstrapping
			// synchronously, so missing the window means the Mithril path was
			// never exercised — that's a failure, not a benign race.
			if !sawBootstrapping {
				t.Fatal("node became servable without an observed bootstrapping window; Mithril path not exercised")
			}
			if st.Bootstrap != nil {
				t.Fatalf("Bootstrap should be cleared once serving, got %+v", st.Bootstrap)
			}
			return // success
		case StateError:
			t.Fatalf("bootstrap errored: %s", st.Err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not reach a servable state in time (a full run needs -timeout 25m or more); last = %s", st.State)
		}
		time.Sleep(3 * time.Second)
	}
}
