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
	"testing"
)

// TestStartWhileRunningReturnsErrAlreadyStarted verifies the start guard: a
// second Start must not overwrite the active node's cancel function and orphan
// its goroutines.
func TestStartWhileRunningReturnsErrAlreadyStarted(t *testing.T) {
	s := New(Config{Network: "preview", DataDir: t.TempDir()})
	s.nodeFactory = fakeNodeFactory{}

	// Start the supervisor so the cancel guard is set.
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("first Start = %v, want nil", err)
	}
	t.Cleanup(s.Stop)

	// Verify the cancel guard is occupied.
	s.mu.Lock()
	guard := s.cancel
	s.mu.Unlock()
	if guard == nil {
		t.Fatal("expected cancel guard to be set after Start")
	}

	// A direct Start while running must return ErrAlreadyStarted — not nil
	// (which would silently accept a double-start bug) and not some other error.
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("Start while running returned nil; expected ErrAlreadyStarted")
	}
	if !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("Start while running = %v, want ErrAlreadyStarted", err)
	}

}
