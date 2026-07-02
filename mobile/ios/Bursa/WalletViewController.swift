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

        // Boot the wallet in-process. The Documents dir is the app's writable
        // data dir; "preview" is the network; lean = true selects the
        // history-expiry profile (small on-disk footprint) for a phone.
        let dataDir = NSSearchPathForDirectoriesInDomains(
            .documentDirectory, .userDomainMask, true
        ).first ?? NSTemporaryDirectory()

        startWallet(dataDir: dataDir)
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
                NSLog("bursa: wallet start failed: \(error)")
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
                NSLog("bursa: wallet returned invalid port \(port)")
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
    func onResume() {
        let currentApp = syncState { () -> MobileApp? in
            stopping ? nil : app
        }
        do {
            try currentApp?.onResume()
        } catch {
            NSLog("bursa: wallet resume failed: \(error)")
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
            NSLog("bursa: wallet stop failed: \(error)")
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
