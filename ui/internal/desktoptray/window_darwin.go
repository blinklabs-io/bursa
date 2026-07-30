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

//go:build webview && darwin

package desktoptray

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// desktopTrayCloseRequested is implemented in Go (see the //export below).
extern void desktopTrayCloseRequested(void);

// BursaWindowDelegate intercepts the window's red close button and its yellow
// minimize button. Returning NO from windowShouldClose: keeps the NSWindow (and
// the embedded node) alive; the Go side hides it to the tray. AppKit has no
// cancelable "should miniaturize" hook, so minimize is caught in
// windowDidMiniaturize: — by then the window has already miniaturized, so the Go
// hide path (desktop_tray_hide) deminiaturizes before ordering it out, leaving
// no Dock tile behind. Both routes funnel through the one hide-to-tray path.
// This replaces any delegate the webview set, which is intended: we want close
// and minimize to hide, not terminate or sit in the Dock.
@interface BursaWindowDelegate : NSObject <NSWindowDelegate>
@end

@implementation BursaWindowDelegate
- (BOOL)windowShouldClose:(NSWindow *)sender {
	(void)sender;
	desktopTrayCloseRequested();
	return NO; // keep the window; Go orders it out to the tray
}
- (void)windowDidMiniaturize:(NSNotification *)notification {
	(void)notification;
	desktopTrayCloseRequested(); // Go hides to the tray (and deminiaturizes)
}
@end

static BursaWindowDelegate *g_desktop_tray_delegate = nil;

// desktop_tray_install_close sets our close-intercepting delegate. Must run on
// the AppKit main thread; the desktop shell calls this on the main goroutine
// (runtime.LockOSThread) before [NSApp run].
static void desktop_tray_install_close(void *window) {
	NSWindow *win = (NSWindow *)window;
	if (g_desktop_tray_delegate == nil) {
		g_desktop_tray_delegate = [[BursaWindowDelegate alloc] init];
	}
	[win setDelegate:g_desktop_tray_delegate];
}

// desktop_tray_hide orders the window out and drops the app to accessory
// activation so only the tray item remains (no Dock icon / menu bar). If the
// window arrived here via a minimize (windowDidMiniaturize:), it is still
// miniaturized; deminiaturize first so ordering it out leaves no minimized Dock
// tile and the next show restores a normal window.
static void desktop_tray_hide(void *window) {
	NSWindow *win = (NSWindow *)window;
	if ([win isMiniaturized]) {
		[win deminiaturize:nil];
	}
	[win orderOut:nil];
	[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
}

// desktop_tray_show restores regular activation, brings the app forward and
// makes the window key + front.
static void desktop_tray_show(void *window) {
	NSWindow *win = (NSWindow *)window;
	[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
	[NSApp activateIgnoringOtherApps:YES];
	[win makeKeyAndOrderFront:nil];
}
*/
import "C"

import "unsafe"

// cocoaWindow controls the webview's NSWindow.
type cocoaWindow struct{ ptr unsafe.Pointer }

func newWindowController(handle unsafe.Pointer) WindowController {
	return &cocoaWindow{ptr: handle}
}

func (c *cocoaWindow) Show() {
	if c.ptr == nil {
		return
	}
	C.desktop_tray_show(c.ptr)
}

func (c *cocoaWindow) Hide() {
	if c.ptr == nil {
		return
	}
	C.desktop_tray_hide(c.ptr)
}

func (c *cocoaWindow) OnCloseRequested(fn func()) {
	setCloseHandler(fn)
	if c.ptr == nil {
		return
	}
	C.desktop_tray_install_close(c.ptr)
}

//export desktopTrayCloseRequested
func desktopTrayCloseRequested() { fireCloseHandler() }
