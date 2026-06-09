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
