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

import UIKit
import WebKit
import OSLog

// Mobile is the gomobile-generated framework. `gomobile bind -target=ios`
// compiles the Go `mobile` package into Bursa.xcframework; the Go package name
// becomes the Objective-C symbol prefix `Mobile`. So the Go `App` struct is the
// class `MobileApp`, and the Go `New()` constructor is the free function
// `MobileNew()`. (Bursa.xcframework is the framework module Swift imports.)
import Bursa

// WalletViewController boots the in-process wallet (the embedded lean Dingo node
// + the loopback control surface serving the API and the embedded SPA), then
// points a full-screen WKWebView at the loopback URL the wallet chose.
class WalletViewController: UIViewController, WKNavigationDelegate {

    // os.Logger redacts dynamic string interpolations (e.g. error descriptions,
    // which could carry file paths) by default, unlike NSLog which writes raw
    // text into the public system log console.
    private static let logger = Logger(subsystem: "io.blinklabs.bursa", category: "wallet")

    private var app: MobileApp?
    private var webView: WKWebView!
    private var walletPort = 0
    private static let stateQueueKey = DispatchSpecificKey<String>()
    private let stateQueue: DispatchQueue = {
        let queue = DispatchQueue(label: "io.blinklabs.bursa.wallet.state")
        queue.setSpecific(key: WalletViewController.stateQueueKey, value: "state")
        return queue
    }()
    private var stopping = false
    // Set by walletDataDirectory when it fell back to the legacy tree, and
    // cleared by the first presentation. Main-thread only: written from
    // viewDidLoad, read from viewDidAppear.
    private var migrationFailureDetail: String?

    override func loadView() {
        let config = WKWebViewConfiguration()
        // The SPA uses DOM storage; WKWebView enables JavaScript by default.
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        self.webView = webView
        view = webView
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        // Boot the wallet in-process. Application Support is durable,
        // app-private storage intended for databases and support files; keeping
        // the node and wallet tree there avoids treating it as user documents.
        // "preview" is the network; lean = true selects the history-expiry
        // profile (small on-disk footprint) for a phone.
        let dataDir = walletDataDirectory().path

        startWallet(dataDir: dataDir)
    }

    // A failed migration leaves the wallet running from the legacy directory.
    // That is the safe directory to run from, but it is not the intended one,
    // so it is reported rather than left to the system log. Presented here
    // because viewDidLoad runs before this controller is in a window.
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard let detail = migrationFailureDetail else { return }
        migrationFailureDetail = nil
        let alert = UIAlertController(
            title: "Wallet data was not moved",
            message: "Bursa could not move its data into private app storage and "
                + "is running from the previous location. It will try again on the "
                + "next launch.\n\n\(detail)",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Continue", style: .default, handler: nil))
        present(alert, animated: true)
    }

    // Written only after a migration has copied and verified every entry, so
    // its absence means any content in the destination is a partial copy.
    private static let migrationCompleteMarker = ".migration-complete"

    private func walletDataDirectory() -> URL {
        let fileManager = FileManager.default
        guard let applicationSupport = fileManager.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first else {
            return URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        }
        let dataDir = applicationSupport.appendingPathComponent("Bursa", isDirectory: true)
        let documentsDir = fileManager.urls(
            for: .documentDirectory, in: .userDomainMask
        ).first

        let marker = dataDir.appendingPathComponent(
            Self.migrationCompleteMarker, isDirectory: false
        )

        var copiedEntries: [URL] = []
        do {
            try fileManager.createDirectory(
                at: dataDir, withIntermediateDirectories: true
            )
            // Before anything is written or copied in, so the tree is never
            // eligible for a backup that starts mid-migration.
            Self.excludeFromBackup(dataDir)
            if let documentsDir,
               fileManager.fileExists(atPath: documentsDir.path),
               try !fileManager.contentsOfDirectory(atPath: documentsDir.path).isEmpty {
                // A finished migration leaves the marker behind. Without it,
                // anything already in dataDir is an interrupted copy rather
                // than an authoritative tree — the legacy directory is still
                // the real one, since its contents are only removed after the
                // copy has been verified — so discard the remnants and copy
                // again. Treating a partial tree as authoritative is how a
                // kill mid-copy turned into a wallet that starts against half
                // its data.
                if fileManager.fileExists(atPath: marker.path) {
                    // A finished migration can still have left the legacy tree
                    // in place: removing it is allowed to fail and be deferred
                    // so a complete copy is never discarded over a cleanup
                    // error. The marker records what the migration copied, so
                    // a later launch finishes the removal against exactly
                    // those names and leaves anything written to Documents
                    // since then alone.
                    Self.removeMigratedLegacyEntries(
                        fileManager: fileManager,
                        marker: marker,
                        documentsDir: documentsDir
                    )
                    return dataDir
                }
                for stale in try fileManager.contentsOfDirectory(atPath: dataDir.path) {
                    try fileManager.removeItem(
                        at: dataDir.appendingPathComponent(stale)
                    )
                }
                let entries = try fileManager.contentsOfDirectory(
                    at: documentsDir,
                    includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles]
                )
                for entry in entries {
                    let destination = dataDir.appendingPathComponent(entry.lastPathComponent)
                    try fileManager.copyItem(at: entry, to: destination)
                    copiedEntries.append(destination)
                }
                let migrated = try fileManager.contentsOfDirectory(
                    at: dataDir,
                    includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles]
                )
                guard Set(migrated.map(\.lastPathComponent)) == Set(entries.map(\.lastPathComponent)) else {
                    throw NSError(domain: "BursaWalletMigration", code: 1)
                }
                // Only now, with every entry copied and checked, does the copy
                // become the authoritative one.
                try JSONSerialization.data(
                    withJSONObject: entries.map(\.lastPathComponent),
                    options: []
                ).write(to: marker, options: .atomic)
                do {
                    for entry in entries {
                        try fileManager.removeItem(at: entry)
                    }
                } catch {
                    Self.logger.error("wallet legacy cleanup deferred: \(String(describing: error))")
                    return dataDir
                }
            }
            return dataDir
        } catch {
            for entry in copiedEntries { try? fileManager.removeItem(at: entry) }
            Self.logger.error("wallet data migration failed: \(String(describing: error))")
            // The legacy tree is only emptied after the copy has been verified,
            // so on failure it is still the authoritative one and the
            // destination holds nothing but the rolled-back partial copy.
            // Booting against the destination would show an empty wallet, and
            // the next launch would then discard whatever was created in it.
            // So keep using the legacy directory — but surface the failure:
            // silently running from the directory the app is migrating away
            // from is how a one-off copy error becomes a permanent second tree.
            let fallback = documentsDir ?? dataDir
            Self.excludeFromBackup(fallback)
            migrationFailureDetail = error.localizedDescription
            return fallback
        }
    }

    // Set on every launch, not once at creation: the flag is a per-URL resource
    // value, so an install that predates it, or a directory restored from an
    // older backup, has the directory present without it. Re-setting an
    // already-excluded URL is a no-op.
    //
    // Application Support + this flag, rather than Library/Caches: the system
    // may purge Caches at any time, and vault.json is the encrypted wallet
    // seeds, which cannot be regenerated by re-syncing.
    private static func excludeFromBackup(_ url: URL) {
        var url = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        do {
            try url.setResourceValues(values)
        } catch {
            logger.error("wallet backup exclusion failed: \(String(describing: error))")
        }
    }

    // Removes the legacy entries a completed migration recorded in its marker.
    // Only the recorded names are touched, so a file written to Documents
    // after the migration is never deleted. A marker that predates the record
    // (or is unreadable) names nothing and removes nothing.
    private static func removeMigratedLegacyEntries(
        fileManager: FileManager,
        marker: URL,
        documentsDir: URL
    ) {
        guard let recorded = try? Data(contentsOf: marker),
              let object = try? JSONSerialization.jsonObject(
                  with: recorded, options: []
              ),
              let names = object as? [String] else {
            return
        }
        for name in names {
            let legacy = documentsDir.appendingPathComponent(name)
            guard fileManager.fileExists(atPath: legacy.path) else { continue }
            do {
                try fileManager.removeItem(at: legacy)
            } catch {
                logger.error("wallet legacy cleanup deferred: \(String(describing: error))")
            }
        }
    }

    private func startWallet(dataDir: String) {
        let app = MobileNew()
        stateQueue.async { [weak self] in
            guard let self = self else {
                Self.stopApp(app)
                return
            }
            guard !self.stopping else {
                return
            }
            self.app = app

            do {
                try app?.start(dataDir, network: "preview", lean: true)
            } catch {
                Self.logger.error("wallet start failed: \(String(describing: error))")
                Self.stopApp(app)
                self.app = nil
                DispatchQueue.main.async { [weak self] in
                    self?.showStartupError("Wallet failed to start", detail: error.localizedDescription)
                }
                return
            }

            // app.port() is the OS-assigned loopback port the control surface bound.
            let port = app?.port() ?? 0
            guard port > 0, let url = URL(string: "http://127.0.0.1:\(port)/") else {
                Self.logger.error("wallet returned invalid port \(port)")
                self.app = nil
                Self.stopApp(app)
                DispatchQueue.main.async { [weak self] in
                    self?.showStartupError(
                        "Wallet failed to start",
                        detail: "The wallet did not bind to a valid port."
                    )
                }
                return
            }

            DispatchQueue.main.async { [weak self] in
                guard let self = self else {
                    Self.stopApp(app)
                    return
                }
                guard self.shouldUseStartedApp() else {
                    Self.stopApp(app)
                    return
                }
                self.walletPort = port
                self.webView.load(URLRequest(url: url))
            }
        }
    }

    private func shouldUseStartedApp() -> Bool {
        syncState {
            !stopping && app != nil
        }
    }

    private func showStartupError(_ title: String, detail: String) {
        if syncState({ !stopping && app == nil }) {
            showError(title, detail: detail)
        }
    }

    // onResume re-dials the node's peers after the app returns from the
    // background. Called by AppDelegate.applicationWillEnterForeground.
    //
    // The Go-side call is a blocking node Stop+relaunch cycle (seconds), so it
    // must never run synchronously on the caller's thread. AppDelegate already
    // hops to a background queue before calling this, but dispatching onto
    // stateQueue here too makes the method itself safe regardless of caller,
    // and serializes it against startWallet/stopWallet's state mutations.
    func onResume() {
        stateQueue.async { [weak self] in
            guard let self = self, !self.stopping else { return }
            do {
                try self.app?.onResume()
            } catch {
                Self.logger.error("wallet resume failed: \(String(describing: error))")
            }
        }
    }

    // onNetworkChanged re-dials the node's peers after a host connectivity
    // transition (WiFi<->cellular, loss->regain). Called by AppDelegate's
    // NWPathMonitor callback, debounced there the same way Android's
    // ConnectivityManager.NetworkCallback debounces onAvailable/onLost.
    //
    // Same threading contract as onResume: the Go-side call is a blocking node
    // Stop+relaunch cycle, so it always hops onto stateQueue rather than
    // running on the caller's thread, and self.app?.onNetworkChanged() is a
    // documented no-op before Start/after Stop.
    func onNetworkChanged() {
        stateQueue.async { [weak self] in
            guard let self = self, !self.stopping else { return }
            do {
                try self.app?.onNetworkChanged()
            } catch {
                Self.logger.error("wallet network-changed failed: \(String(describing: error))")
            }
        }
    }

    // stopWallet tears the wallet down cleanly. Called by AppDelegate on
    // applicationWillTerminate. deinit handles the normal destroy path.
    func stopWallet() {
        stopWalletLogged()
    }

    private func stopWalletLogged() {
        let currentApp = syncState { () -> MobileApp? in
            stopping = true
            let current = app
            app = nil
            return current
        }
        Self.stopApp(currentApp)
    }

    private static func stopApp(_ app: MobileApp?) {
        do {
            try app?.stop()
        } catch {
            logger.error("wallet stop failed: \(String(describing: error))")
        }
    }

    private func syncState<T>(_ work: () -> T) -> T {
        if DispatchQueue.getSpecific(key: Self.stateQueueKey) != nil {
            return work()
        }
        return stateQueue.sync {
            work()
        }
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.cancel)
            return
        }
        if isWalletURL(url) || url.scheme == "about" {
            decisionHandler(.allow)
            return
        }

        decisionHandler(.cancel)
        if navigationAction.targetFrame?.isMainFrame ?? true {
            showError("Blocked navigation", detail: "The wallet blocked navigation to \(url.absoluteString).")
        }
    }

    private func isWalletURL(_ url: URL) -> Bool {
        guard url.scheme == "http", walletPort > 0, url.port == walletPort else {
            return false
        }
        guard let host = url.host?.lowercased() else {
            return false
        }
        return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
    }

    // showError renders a minimal inline error page when the wallet fails to
    // boot, replacing the blank WebView the user would otherwise see.
    private func showError(_ title: String, detail: String) {
        let escaped = detail
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
        let html = """
        <!doctype html>
        <html>
        <head>
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <style>
            body{font-family:sans-serif;margin:0;padding:24px;background:#111;color:#eee;
                 display:flex;flex-direction:column;justify-content:center;min-height:100vh}
            h1{font-size:1.25rem;margin:0 0 12px}
            p{margin:0;color:#bbb;line-height:1.5;word-break:break-word}
          </style>
        </head>
        <body>
          <h1>\(title)</h1>
          <p>\(escaped)</p>
        </body>
        </html>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }

    deinit {
        // Tear the wallet down: drains the control surface and winds down the
        // in-process node.
        stopWalletLogged()
    }
}
