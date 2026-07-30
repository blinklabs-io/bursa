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

// Package desktoptray adds a system-tray item plus minimize/close-to-tray
// behaviour to the -tags webview desktop wallet. It is a single-process
// ("Option B") design: the tray shares the one webview run loop rather than
// spawning a second controller process, so closing or minimizing the window
// merely hides it (the embedded node keeps running) while Quit performs a real
// shutdown.
//
// This file is deliberately free of build tags, cgo and the systray dependency
// so the show/hide state machine is unit-testable in the pure-Go CI without a
// display. The platform-specific glue (systray, the tray menu-action routing,
// the per-OS window cgo) lives in the webview-tagged files.
package desktoptray

import "sync"

// WindowController manipulates the single native desktop window behind the
// webview. Implementations are per-OS cgo (window_darwin.go / window_linux.go /
// window_windows.go) over the pointer returned by webview.WebView.Window().
//
// Every method touches native UI objects (NSWindow / GtkWindow / HWND) and so
// must run on the UI thread; the Controller marshals each call through the
// webview's dispatcher before invoking these methods, so implementations can
// assume they are already on that thread.
type WindowController interface {
	// Show makes the window visible and brings it to the front.
	Show()
	// Hide removes the window from the screen without destroying it, leaving
	// only the tray item. The node and control surface keep running.
	Hide()
	// OnCloseRequested installs the native close and minimize interception
	// (macOS windowShouldClose: + windowDidMiniaturize:, GTK delete-event +
	// window-state-event, Win32 WM_CLOSE + WM_SYSCOMMAND/SC_MINIMIZE) so a user
	// close or minimize invokes fn instead of destroying or minimizing the
	// window.
	OnCloseRequested(fn func())
}

// Controller owns the window show/hide policy and the Quit path. It is the
// single place that decides "close hides, Quit terminates", kept UI-toolkit and
// OS agnostic so it can be exercised without a tray or a window.
type Controller struct {
	win       WindowController
	dispatch  func(func())
	terminate func()

	mu     sync.Mutex
	hidden bool
}

// NewController wires a Controller.
//
//   - win manipulates the native window (Show/Hide/close-interception).
//   - dispatch runs a closure on the webview UI thread (webview.Dispatch). A nil
//     dispatch runs closures inline, which is what the unit tests use.
//   - terminate ends the webview run loop (webview.Terminate); this is the Quit
//     path that lets the caller tear the whole stack down.
func NewController(win WindowController, dispatch func(func()), terminate func()) *Controller {
	if dispatch == nil {
		dispatch = func(f func()) { f() }
	}
	c := &Controller{win: win, dispatch: dispatch, terminate: terminate}
	// A user close must hide (keep the node running), never destroy the window.
	if win != nil {
		win.OnCloseRequested(c.HandleWindowClose)
	}
	return c
}

// Show reveals the window and clears the hidden flag. Safe to call from any
// goroutine (e.g. the tray click loop); the native work is marshalled onto the
// UI thread.
func (c *Controller) Show() {
	c.dispatch(func() {
		if c.win != nil {
			c.win.Show()
		}
		c.setHidden(false)
	})
}

// Hide removes the window to the tray and sets the hidden flag. The node keeps
// running.
func (c *Controller) Hide() {
	c.dispatch(func() {
		if c.win != nil {
			c.win.Hide()
		}
		c.setHidden(true)
	})
}

// HandleWindowClose is the target of the native close-interception hook. Closing
// or minimizing the window hides it rather than quitting, so the wallet keeps
// syncing in the background and re-opens instantly from the tray.
func (c *Controller) HandleWindowClose() { c.Hide() }

// Quit performs a real shutdown by ending the webview run loop, which unblocks
// the desktop shell so it can stop the boot stack (node + control surface). It
// is a no-op when no terminate function was supplied.
func (c *Controller) Quit() {
	if c.terminate == nil {
		return
	}
	c.dispatch(c.terminate)
}

// Hidden reports whether the window is currently hidden to the tray.
func (c *Controller) Hidden() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hidden
}

func (c *Controller) setHidden(v bool) {
	c.mu.Lock()
	c.hidden = v
	c.mu.Unlock()
}
