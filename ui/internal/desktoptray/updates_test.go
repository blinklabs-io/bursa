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

package desktoptray

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/updatecheck"
)

func newTestUpdateChecker(done chan struct{}, check func(context.Context) (updatecheck.Release, bool, error)) (*UpdateChecker, *atomic.Int32, *atomic.Int32) {
	var notifies, opens atomic.Int32
	u := &UpdateChecker{
		check:  check,
		notify: func(string, string) { notifies.Add(1) },
		open:   func(string) { opens.Add(1) },
		done:   done,
	}
	return u, &notifies, &opens
}

func TestUpdateCheckerRunsOneCheckAtATime(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	u, _, _ := newTestUpdateChecker(make(chan struct{}), func(context.Context) (updatecheck.Release, bool, error) {
		calls.Add(1)
		<-release
		return updatecheck.Release{TagName: "v1.0.0"}, false, nil
	})
	finished := make(chan struct{}, 2)
	if !u.Start(func() { finished <- struct{}{} }) {
		t.Fatal("first Start did not start a check")
	}
	if u.Start(func() { finished <- struct{}{} }) {
		t.Fatal("second Start started a check while one was running")
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("check did not finish")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("check ran %d times, want 1", got)
	}
	if !u.Start(func() {}) {
		t.Fatal("Start after the check finished did not start a new check")
	}
}

func TestUpdateCheckerStopPreventsStart(t *testing.T) {
	var calls atomic.Int32
	u, _, _ := newTestUpdateChecker(make(chan struct{}), func(context.Context) (updatecheck.Release, bool, error) {
		calls.Add(1)
		return updatecheck.Release{}, false, nil
	})
	u.Stop()
	if u.Start(func() {}) {
		t.Fatal("Start succeeded after Stop")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("check ran %d times after Stop, want 0", got)
	}
}

func TestUpdateCheckerStopCancelsCheckAndDropsResult(t *testing.T) {
	done := make(chan struct{})
	u, notifies, opens := newTestUpdateChecker(done, func(ctx context.Context) (updatecheck.Release, bool, error) {
		<-ctx.Done()
		return updatecheck.Release{TagName: "v9.9.9", HTMLURL: "https://github.com/blinklabs-io/bursa/releases/tag/v9.9.9"}, true, nil
	})
	var finished atomic.Bool
	returned := make(chan struct{})
	go func() {
		u.run(func() { finished.Store(true) })
		close(returned)
	}()
	close(done)
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("stopping the tray did not cancel the in-flight check")
	}
	if notifies.Load() != 0 || opens.Load() != 0 || finished.Load() {
		t.Fatalf("check after stop had side effects: notifies=%d opens=%d finished=%v",
			notifies.Load(), opens.Load(), finished.Load())
	}
}

func TestUpdateCheckerDoesNotOpenOrFinishAfterNotificationStopsTray(t *testing.T) {
	done := make(chan struct{})
	var opens, finishes atomic.Int32
	u, _, _ := newTestUpdateChecker(done, func(context.Context) (updatecheck.Release, bool, error) {
		return updatecheck.Release{TagName: "v9.9.9", HTMLURL: "https://github.com/blinklabs-io/bursa/releases/tag/v9.9.9"}, true, nil
	})
	u.notify = func(string, string) { close(done) }
	u.open = func(string) { opens.Add(1) }
	u.run(func() { finishes.Add(1) })
	if opens.Load() != 0 || finishes.Load() != 0 {
		t.Fatalf("callbacks ran after tray stopped: opens=%d finishes=%d", opens.Load(), finishes.Load())
	}
}
