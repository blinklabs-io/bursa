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
class WalletViewController: UIViewController {

    private var app: MobileApp?
    private var webView: WKWebView!

    override func loadView() {
        let config = WKWebViewConfiguration()
        // The SPA uses DOM storage; WKWebView enables JavaScript by default.
        let webView = WKWebView(frame: .zero, configuration: config)
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

        let app = MobileNew()
        do {
            try app?.start(dataDir, network: "preview", lean: true)
        } catch {
            NSLog("bursa: wallet start failed: \(error)")
            return
        }
        self.app = app

        // app.port() is the OS-assigned loopback port the control surface bound.
        let port = app?.port() ?? 0
        if let url = URL(string: "http://127.0.0.1:\(port)/") {
            webView.load(URLRequest(url: url))
        }
    }

    deinit {
        // Tear the wallet down: drains the control surface and winds down the
        // in-process node.
        try? app?.stop()
    }
}
