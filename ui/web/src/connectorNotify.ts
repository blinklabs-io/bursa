// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// connectorNotify.ts — Web Notification helper for new CIP-30 consent requests.
//
// CAVEAT: the Bursa desktop app uses webview_go, which embeds a system WebView
// (WebKitGTK on Linux, WKWebView on macOS, WebView2 on Windows). None of these
// expose a native "bring window to front" API from inside the page, so
// window.focus() is best-effort — it will not reliably raise the window above
// other apps. This is documented here rather than silently swallowed.
//
// Permission is requested lazily (once) on the first call to notifyPending. If
// the user denies, subsequent calls are no-ops and do not throw.

import type { ConnectorRequest } from "./api/types";

let permissionRequested = false;

// requestPermission asks for notification permission once and caches the
// result. Subsequent calls are no-ops.
async function requestPermission(): Promise<void> {
  if (permissionRequested) return;
  permissionRequested = true;
  if (typeof Notification === "undefined") return;
  if (Notification.permission === "default") {
    await Notification.requestPermission();
  }
}

// notifyPending fires a Web Notification for a new connector request and
// attempts to bring the window to the foreground. Safe to call unconditionally:
//
//   - If the Notification API is absent (e.g. test environments that omit it),
//     or the user has denied permission, the function is a no-op.
//   - It never throws — any error is swallowed so that the approval UI is never
//     blocked by a notification failure.
export async function notifyPending(req: ConnectorRequest): Promise<void> {
  try {
    await requestPermission();
    if (typeof Notification === "undefined") return;
    if (Notification.permission !== "granted") return;

    const title = "Bursa — dApp request";
    const body = `${req.origin} is requesting: ${req.method}`;
    // eslint-disable-next-line no-new
    new Notification(title, {
      body,
      tag: `connector-${req.id}`, // collapse duplicates for the same request
      icon: undefined,            // let the OS use the app icon
    });

    // Best-effort window raise: see CAVEAT above.
    window.focus();
  } catch {
    // Swallow — notification failure must never block the approval UI.
  }
}
