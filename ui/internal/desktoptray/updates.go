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
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/desktopnotify"
	"github.com/blinklabs-io/bursa/ui/internal/openexternal"
	"github.com/blinklabs-io/bursa/ui/internal/updatecheck"
)

const updateCheckTimeout = 10 * time.Second

// UpdateChecker runs the tray's manual "Check for updates" action. It is kept
// free of systray so its lifecycle can be tested headless: at most one check
// runs at a time, and once done is closed an in-flight check is cancelled and
// its result dropped, so nothing is notified or opened after the tray stops.
type UpdateChecker struct {
	check    func(context.Context) (updatecheck.Release, bool, error)
	notify   func(title, body string)
	open     func(url string)
	done     <-chan struct{}
	devBuild bool
	running  atomic.Bool
}

// NewUpdateChecker returns an UpdateChecker for the build's embedded version
// that stops acting once done is closed.
func NewUpdateChecker(currentVersion string, done <-chan struct{}, logger *slog.Logger) *UpdateChecker {
	return &UpdateChecker{
		check: func(ctx context.Context) (updatecheck.Release, bool, error) {
			release, update, err := updatecheck.Check(ctx, nil, currentVersion)
			if err != nil {
				logger.Warn("failed to check for wallet updates", "error", err)
			}
			return release, update, err
		},
		notify:   func(title, body string) { _ = desktopnotify.Notify(logger, title, body) },
		open:     func(url string) { openexternal.Open(logger, url) },
		done:     done,
		devBuild: updatecheck.DevelopmentBuild(currentVersion),
	}
}

// Start begins a check in the background unless one is already running, and
// reports whether it started one. finished runs when the check ends, unless the
// tray was stopped first.
func (u *UpdateChecker) Start(finished func()) bool {
	if !u.running.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer u.running.Store(false)
		u.run(finished)
	}()
	return true
}

func (u *UpdateChecker) run(finished func()) {
	ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	defer cancel()
	go func() {
		select {
		case <-u.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	release, update, err := u.check(ctx)
	select {
	case <-u.done:
		return
	default:
	}
	defer finished()
	switch {
	case err != nil:
		u.notify("Bursa Wallet", "Could not check for updates")
	case update:
		u.notify("Bursa Wallet update available", "Bursa "+release.TagName+" is available")
		u.open(release.HTMLURL)
	case u.devBuild:
		u.notify("Bursa Wallet", "Latest release: "+release.TagName)
	default:
		u.notify("Bursa Wallet", "You are up to date")
	}
}
