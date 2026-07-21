// Ambient bridge injected by the desktop (webview) build only.
//
// `ui/cmd/bursa-wallet/ui_webview.go` binds `bursaOpenExternal` into the
// window's JS context via `webview.Bind` so that clicking an external link
// (see components/ExplorerLink.tsx) opens the OS's default browser instead
// of navigating the embedded webview itself. The headless (browser) build
// never injects this, so callers must always feature-detect before use.
export {};

declare global {
  interface Window {
    bursaOpenExternal?: (url: string) => void;
  }
}
