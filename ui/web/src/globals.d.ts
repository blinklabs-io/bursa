// Ambient bridges injected by the desktop (webview) build only.
//
// `ui/cmd/bursa-wallet/ui_webview.go` binds these into the window's JS context
// via `webview.Bind`:
//   - `bursaOpenExternal` opens an external link in the OS's default browser
//     instead of navigating the embedded webview (see components/ExplorerLink.tsx).
//   - `bursaNotify` raises a real OS-native notification for a wallet-activity
//     event; the plain browser build falls back to the Notification API (see
//     notifications.ts). It resolves to whether the notifier actually started
//     — webview.Bind always returns a promise-wrapped result to JS, hence the
//     `boolean | Promise<boolean>` union rather than a plain boolean.
// The headless (browser) build never injects these, so callers must always
// feature-detect before use.
export {};

declare global {
  interface Window {
    bursaOpenExternal?: (url: string) => void;
    bursaNotify?: (title: string, body: string) => boolean | Promise<boolean>;
  }
}
