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

//go:build webview && linux

package desktoptray

/*
#cgo pkg-config: gtk+-3.0
#include <gtk/gtk.h>

// desktopTrayCloseRequested is implemented in Go (see the //export below).
extern void desktopTrayCloseRequested(void);

// on_delete_event fires when the window manager's close button is pressed. The
// webview's own top-level window otherwise emits "destroy" on close, which
// tears the window down. Returning TRUE stops GTK's default handler (which would
// destroy the widget), keeping the window and the embedded node alive; the Go
// side hides the window on the UI thread.
static gboolean desktop_tray_on_delete_event(GtkWidget *w, GdkEvent *e, gpointer data) {
	(void)w; (void)e; (void)data;
	desktopTrayCloseRequested();
	return TRUE; // prevent destruction
}

// desktop_tray_on_window_state fires on every top-level window-state change
// (GTK3 "window-state-event"). A native minimize sets GDK_WINDOW_STATE_ICONIFIED
// in new_window_state; we detect the transition *into* the iconified state
// (changed_mask & new_window_state, a bitwise test per the GTK3 docs) and route
// it through the same close-to-tray path, so a minimize hides the window to the
// tray and keeps the Controller's hidden flag in sync. The window is briefly
// iconified before Go's Hide runs; the Show path (gtk_window_present)
// deiconifies on the way back, so no state leaks. All other state changes fall
// through. Returning FALSE lets GTK's default handling proceed.
static gboolean desktop_tray_on_window_state(GtkWidget *w, GdkEventWindowState *e, gpointer data) {
	(void)w; (void)data;
	if ((e->changed_mask & GDK_WINDOW_STATE_ICONIFIED) &&
	    (e->new_window_state & GDK_WINDOW_STATE_ICONIFIED)) {
		desktopTrayCloseRequested();
	}
	return FALSE; // informational event; do not block default handling
}

static void desktop_tray_install_close(void *window) {
	GtkWidget *w = (GtkWidget *)window;
	g_signal_connect(G_OBJECT(w), "delete-event",
	                 G_CALLBACK(desktop_tray_on_delete_event), NULL);
	g_signal_connect(G_OBJECT(w), "window-state-event",
	                 G_CALLBACK(desktop_tray_on_window_state), NULL);
}

static void desktop_tray_hide(void *window) {
	gtk_widget_hide((GtkWidget *)window);
}

static void desktop_tray_show(void *window) {
	GtkWidget *w = (GtkWidget *)window;
	gtk_widget_show(w);
	gtk_window_present(GTK_WINDOW(w));
}
*/
import "C"

import "unsafe"

// gtkWindow controls the webview's top-level GtkWindow.
type gtkWindow struct{ ptr unsafe.Pointer }

func newWindowController(handle unsafe.Pointer) WindowController {
	return &gtkWindow{ptr: handle}
}

func (g *gtkWindow) Show() {
	if g.ptr == nil {
		return
	}
	C.desktop_tray_show(g.ptr)
}

func (g *gtkWindow) Hide() {
	if g.ptr == nil {
		return
	}
	C.desktop_tray_hide(g.ptr)
}

func (g *gtkWindow) OnCloseRequested(fn func()) {
	setCloseHandler(fn)
	if g.ptr == nil {
		return
	}
	C.desktop_tray_install_close(g.ptr)
}

//export desktopTrayCloseRequested
func desktopTrayCloseRequested() { fireCloseHandler() }
