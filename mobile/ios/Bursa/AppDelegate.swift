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

import Network
import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    // Observes host connectivity so the wallet re-dials peers on a network
    // transition (WiFi<->cellular, loss->regain), mirroring the Android
    // ConnectivityManager.NetworkCallback in WalletService.kt. Lives here
    // (rather than in the view controller) because AppDelegate is the
    // process-lifetime owner, matching where Android hosts its callback.
    private let pathMonitor = NWPathMonitor()
    private let pathMonitorQueue = DispatchQueue(label: "io.blinklabs.bursa.pathmonitor")
    private var reconnectWorkItem: DispatchWorkItem?

    // 500 ms debounce window collapsing back-to-back path updates (e.g. a
    // brief drop during a WiFi<->cellular hand-off) into a single reconnect.
    // Matches WalletService.kt's DEBOUNCE_DELAY_MS.
    private static let networkDebounceDelay: TimeInterval = 0.5

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = WalletViewController()
        window.makeKeyAndVisible()
        self.window = window
        startPathMonitor()
        return true
    }

    // Re-dial peers when the app returns to the foreground. Peer connections go
    // stale during suspension; calling onResume() triggers a node Stop+relaunch
    // cycle that re-establishes them. WalletViewController exposes the wallet via
    // a public accessor so the delegate can reach it here.
    func applicationWillEnterForeground(_ application: UIApplication) {
        guard let vc = window?.rootViewController as? WalletViewController else { return }
        DispatchQueue.global(qos: .utility).async { [weak vc] in
            vc?.onResume()
        }
    }

    // Best-effort termination cleanup. WalletViewController.deinit calls stop()
    // for normal app lifecycle; applicationWillTerminate gives one last short
    // synchronous window when iOS delivers the termination callback.
    func applicationWillTerminate(_ application: UIApplication) {
        pathMonitor.cancel()
        guard let vc = window?.rootViewController as? WalletViewController else { return }
        vc.stopWallet()
    }

    // startPathMonitor begins observing host connectivity for the process
    // lifetime. Every path update (gained or lost) is debounced and forwarded
    // to WalletViewController.onNetworkChanged(), which is a safe no-op before
    // the wallet has started or after it has stopped — so it is safe to start
    // this immediately at launch rather than gating it on boot completion.
    private func startPathMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            self?.scheduleReconnect()
        }
        pathMonitor.start(queue: pathMonitorQueue)
    }

    // scheduleReconnect (re)starts the debounce window, coalescing rapid
    // connectivity flaps into a single reconnect. Runs on pathMonitorQueue.
    private func scheduleReconnect() {
        reconnectWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            // window/rootViewController are UIKit and must be read on main.
            DispatchQueue.main.async { [weak self] in
                guard let vc = self?.window?.rootViewController as? WalletViewController else { return }
                vc.onNetworkChanged()
            }
        }
        reconnectWorkItem = workItem
        pathMonitorQueue.asyncAfter(deadline: .now() + Self.networkDebounceDelay, execute: workItem)
    }
}
