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
	"sync"
	"testing"
)

// fakeWindow records native window calls so the pure show/hide/close policy can
// be asserted without a display or cgo.
type fakeWindow struct {
	mu        sync.Mutex
	shows     int
	hides     int
	onClose   func()
	closeHook bool
}

func (f *fakeWindow) Show() {
	f.mu.Lock()
	f.shows++
	f.mu.Unlock()
}

func (f *fakeWindow) Hide() {
	f.mu.Lock()
	f.hides++
	f.mu.Unlock()
}

func (f *fakeWindow) OnCloseRequested(fn func()) {
	f.mu.Lock()
	f.onClose = fn
	f.closeHook = true
	f.mu.Unlock()
}

func (f *fakeWindow) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.shows, f.hides
}

// newTestController wires a Controller with a synchronous dispatcher so state
// transitions are observable immediately after each call.
func newTestController(t *testing.T) (*Controller, *fakeWindow, *int) {
	t.Helper()
	win := &fakeWindow{}
	var quits int
	c := NewController(win, nil /* inline dispatch */, func() { quits++ })
	return c, win, &quits
}

func TestNewControllerInstallsCloseHook(t *testing.T) {
	_, win, _ := newTestController(t)
	if !win.closeHook {
		t.Fatal("NewController did not install the native close-interception hook")
	}
	if win.onClose == nil {
		t.Fatal("close hook registered a nil handler")
	}
}

func TestCloseHidesRatherThanQuits(t *testing.T) {
	c, win, quits := newTestController(t)

	// A fresh controller starts shown.
	if c.Hidden() {
		t.Fatal("controller should start in the shown state")
	}

	// Simulate the native close/minimize interception firing.
	win.onClose()

	if !c.Hidden() {
		t.Fatal("close should hide the window (hidden flag not set)")
	}
	if _, hides := win.counts(); hides != 1 {
		t.Fatalf("close should hide exactly once, got %d hides", hides)
	}
	if *quits != 0 {
		t.Fatalf("close must not quit; terminate called %d times", *quits)
	}
}

func TestHideShowTransitions(t *testing.T) {
	c, win, _ := newTestController(t)

	c.Hide()
	if !c.Hidden() {
		t.Fatal("Hide should set hidden=true")
	}
	c.Show()
	if c.Hidden() {
		t.Fatal("Show should set hidden=false")
	}
	c.Hide()
	if !c.Hidden() {
		t.Fatal("second Hide should set hidden=true")
	}

	shows, hides := win.counts()
	if shows != 1 {
		t.Fatalf("want 1 native Show, got %d", shows)
	}
	if hides != 2 {
		t.Fatalf("want 2 native Hides, got %d", hides)
	}
}

func TestQuitWithoutTerminateIsNoop(t *testing.T) {
	// A nil terminate must not panic (defensive: the field is caller-supplied).
	c := NewController(&fakeWindow{}, nil, nil)
	c.Quit() // must not panic
}

func TestNilWindowIsSafe(t *testing.T) {
	// The controller tolerates a nil window (no OS hooks) so higher layers can
	// construct it in environments without a native window.
	var quits int
	c := NewController(nil, nil, func() { quits++ })
	c.Show()
	c.Hide()
	if !c.Hidden() {
		t.Fatal("Hide should still track state with a nil window")
	}
	c.Quit()
	if quits != 1 {
		t.Fatalf("Quit should still fire with a nil window, got %d", quits)
	}
}
