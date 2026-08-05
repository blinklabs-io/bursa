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
#cgo LDFLAGS: -framework Cocoa

// Declarations only. The Objective-C definitions live in window_darwin.m, which
// cgo compiles exactly once.
//
// They cannot live in this preamble: the package exports a function to C (see
// the //export below), so cgo copies the preamble into the generated
// _cgo_export translation unit as well as this file's own. Duplicating a
// `static` C function is harmless — that is why the Linux and Windows variants
// keep their callbacks inline — but an Objective-C @implementation always emits
// external symbols (`static` is meaningless for it), so the class would be
// defined in two objects and the link fails with
// "duplicate symbol '_OBJC_CLASS_$_BursaWindowDelegate'".
void desktop_tray_install_close(void *window);
void desktop_tray_hide(void *window);
void desktop_tray_show(void *window);
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
