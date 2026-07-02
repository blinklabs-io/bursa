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

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = WalletViewController()
        window.makeKeyAndVisible()
        self.window = window
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
        guard let vc = window?.rootViewController as? WalletViewController else { return }
        vc.stopWallet()
    }
}
