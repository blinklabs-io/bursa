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

import "context"

// Reconnect re-dials the node's peers after a host network change or app
// resume. It performs a Stop-then-relaunch cycle via the existing
// runID-versioned path, which tears down all peer connections and
// re-establishes them. The already-synced DataDir is preserved and Mithril
// bootstrap is skipped (the completion marker remains), so reconnect is fast
// and involves no data loss.
//
// Reconnect is a safe no-op when the supervisor is not running (not started,
// stopped, or mid-stop). It is concurrency-safe and may be called from the
// Android NetworkCallback or onResume thread.
//
// If the supervisor is already running (Start returns "supervisor already
// started"), Reconnect folds that benign sentinel to nil — the desired
// post-reconnect state is "node running", which is already true.
func (s *Supervisor) Reconnect(ctx context.Context) error {
	s.mu.RLock()
	running := s.cancel != nil
	s.mu.RUnlock()
	if !running {
		return nil
	}
	s.Stop()
	if err := s.Start(ctx); err != nil && err.Error() == "supervisor already started" {
		return nil
	} else {
		return err
	}
}
