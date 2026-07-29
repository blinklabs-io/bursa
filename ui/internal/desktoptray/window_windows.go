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

//go:build webview && windows

package desktoptray

/*
#include <windows.h>

// desktopTrayCloseRequested is implemented in Go (see the //export below).
extern void desktopTrayCloseRequested(void);

static WNDPROC g_desktop_tray_prev_proc = NULL;

// desktop_tray_wndproc subclasses the webview's HWND. WM_CLOSE (the title-bar X)
// is swallowed and reported to Go, which hides the window instead of letting the
// default handler destroy it — the embedded node keeps running. A minimize
// request (WM_SYSCOMMAND with the command bits equal to SC_MINIMIZE — the low 4
// bits are reserved by the system, so mask with 0xFFF0 per the Win32 docs) is
// likewise swallowed and routed through the same hide-to-tray path, so the
// window goes straight to the tray rather than minimizing to the taskbar first.
// All other messages fall through to the original window procedure.
static LRESULT CALLBACK desktop_tray_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
	if (msg == WM_CLOSE) {
		desktopTrayCloseRequested();
		return 0; // swallow: do not destroy
	}
	if (msg == WM_SYSCOMMAND && (wp & 0xFFF0) == SC_MINIMIZE) {
		desktopTrayCloseRequested();
		return 0; // swallow: hide to tray instead of minimizing
	}
	return CallWindowProc(g_desktop_tray_prev_proc, hwnd, msg, wp, lp);
}

static void desktop_tray_install_close(void *hwndPtr) {
	HWND hwnd = (HWND)hwndPtr;
	g_desktop_tray_prev_proc =
		(WNDPROC)(LONG_PTR)SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)desktop_tray_wndproc);
}

static void desktop_tray_hide(void *hwndPtr) {
	ShowWindow((HWND)hwndPtr, SW_HIDE);
}

static void desktop_tray_show(void *hwndPtr) {
	HWND hwnd = (HWND)hwndPtr;
	ShowWindow(hwnd, SW_SHOW);
	SetForegroundWindow(hwnd);
}
*/
import "C"

import "unsafe"

// win32Window controls the webview's HWND.
type win32Window struct{ ptr unsafe.Pointer }

func newWindowController(handle unsafe.Pointer) WindowController {
	return &win32Window{ptr: handle}
}

func (w *win32Window) Show() {
	if w.ptr == nil {
		return
	}
	C.desktop_tray_show(w.ptr)
}

func (w *win32Window) Hide() {
	if w.ptr == nil {
		return
	}
	C.desktop_tray_hide(w.ptr)
}

func (w *win32Window) OnCloseRequested(fn func()) {
	setCloseHandler(fn)
	if w.ptr == nil {
		return
	}
	C.desktop_tray_install_close(w.ptr)
}

//export desktopTrayCloseRequested
func desktopTrayCloseRequested() { fireCloseHandler() }
