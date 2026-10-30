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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrRecoveryUnavailable means the node has not reported a failed sync. A
// clean-data retry is intentionally unavailable while a healthy node is
// running because it discards the local chain database.
var ErrRecoveryUnavailable = errors.New("node recovery is available only after a sync failure")

// Recover removes the embedded node's database and launches a fresh sync. The
// supervisor's DataDir is the node-only boundary supplied by boot; vaults,
// keys, wallet settings, contacts, logs, and caches live outside it.
func (s *Supervisor) Recover(ctx context.Context) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	if s.status.State != StateError {
		s.mu.Unlock()
		return ErrRecoveryUnavailable
	}
	done := s.failedRunDone
	s.failedRunDone = nil
	s.mu.Unlock()

	// The error status is published before the failed run's final goroutine
	// exits. Wait for that completion edge before touching its files.
	s.waitForRunExit(done)
	if err := ctx.Err(); err != nil {
		return err
	}

	if strings.TrimSpace(s.cfg.WalletDataDir) == "" {
		return s.recoveryFailed(errors.New("wallet data directory is not configured"))
	}
	nodeDir, err := filepath.Abs(s.cfg.DataDir)
	if err != nil {
		return s.recoveryFailed(fmt.Errorf("resolve node sync directory: %w", err))
	}
	nodeDir, err = filepath.EvalSymlinks(nodeDir)
	if err != nil {
		return s.recoveryFailed(fmt.Errorf("resolve node sync directory: %w", err))
	}
	walletDir, err := filepath.Abs(s.cfg.WalletDataDir)
	if err != nil {
		return s.recoveryFailed(fmt.Errorf("resolve wallet data directory: %w", err))
	}
	walletDir, err = filepath.EvalSymlinks(walletDir)
	if err != nil {
		return s.recoveryFailed(fmt.Errorf("resolve wallet data directory: %w", err))
	}
	if filepath.Dir(nodeDir) == nodeDir || containsPath(nodeDir, walletDir) {
		return s.recoveryFailed(errors.New("refusing unsafe node sync directory"))
	}
	if err := s.removeAll(nodeDir); err != nil {
		return s.recoveryFailed(fmt.Errorf("remove node sync data: %w", err))
	}
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		return s.recoveryFailed(fmt.Errorf("recreate node sync directory: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return s.recoveryFailed(err)
	}
	if err := s.start(ctx); err != nil {
		return s.recoveryFailed(fmt.Errorf("restart node: %w", err))
	}
	return nil
}

func containsPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func (s *Supervisor) recoveryFailed(err error) error {
	s.mu.Lock()
	s.setStateLocked(StateError)
	s.status.Err = err.Error()
	s.status.Bootstrap = nil
	s.status.BootstrapPhases = nil
	s.mu.Unlock()
	return err
}
