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

//go:build webview

package desktoptray

import "testing"

// These tests cover the tray menu-action routing, which lives in the
// webview-tagged tray.go (its only production consumer is the systray click
// loop). They reuse the tag-free fakeWindow / newTestController helpers from
// controller_test.go, which are compiled into every build. The Controller path
// they exercise never touches cgo or a real window, so it runs headless.

func TestMenuRouteOpenShowsWindow(t *testing.T) {
	c, win, quits := newTestController(t)
	c.Hide() // start hidden as if closed to tray
	c.route(actionOpen)

	if c.Hidden() {
		t.Fatal("Open action should show the window")
	}
	if shows, _ := win.counts(); shows != 1 {
		t.Fatalf("Open should call native Show once, got %d", shows)
	}
	if *quits != 0 {
		t.Fatalf("Open must not quit; terminate called %d times", *quits)
	}
}

func TestMenuRouteQuitTerminates(t *testing.T) {
	c, _, quits := newTestController(t)
	c.route(actionQuit)
	if *quits != 1 {
		t.Fatalf("Quit action should terminate exactly once, got %d", *quits)
	}
}
