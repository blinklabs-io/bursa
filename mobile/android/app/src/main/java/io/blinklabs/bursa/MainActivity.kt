// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package io.blinklabs.bursa

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

// The gomobile binding. `gomobile bind -javapkg io.blinklabs.bursa` emits the Go
// `mobile` package as the Java class `io.blinklabs.bursa.mobile.Mobile`, with
// `App` as `io.blinklabs.bursa.mobile.App`. The Go `New()` constructor becomes
// `Mobile.new_()` (gomobile suffixes the Java keyword `new`).
import io.blinklabs.bursa.mobile.App
import io.blinklabs.bursa.mobile.Mobile

// MainActivity boots the in-process wallet (the embedded lean Dingo node + the
// loopback control surface that serves the API and the embedded SPA), then
// points a full-screen WebView at the loopback URL the wallet chose.
class MainActivity : AppCompatActivity() {

    private lateinit var app: App
    private lateinit var webView: WebView
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // Debounce handler: avoid thrashing Reconnect on rapid network transitions
    // (e.g. WiFi hand-off to cellular). A 500 ms window absorbs back-to-back
    // onLost→onAvailable events from a single interface change.
    private val debounceHandler = Handler(Looper.getMainLooper())
    private val reconnectRunnable = Runnable { handleNetworkChange() }
    private val debounceDelayMs = 500L

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Boot the wallet in-process. filesDir is the app-private writable data
        // dir; "preview" is the network; lean = true selects the history-expiry
        // profile (small on-disk footprint) appropriate for a phone. start()
        // surfaces a boot failure as a (Java-checked) Exception; fail visibly
        // rather than loading a WebView against a port that was never bound.
        app = Mobile.new_()
        try {
            app.start(filesDir.absolutePath, "preview", true)
        } catch (e: Exception) {
            android.util.Log.e("bursa", "wallet start failed", e)
            finish()
            return
        }

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            // The SPA talks to the same loopback origin, so no cross-origin or
            // file-access surface is needed.
            settings.allowFileAccess = false
            settings.allowContentAccess = false
        }
        setContentView(webView)

        // app.port() is the OS-assigned loopback port the control surface bound.
        webView.loadUrl("http://127.0.0.1:${app.port()}/")

        registerNetworkCallback()
    }

    // registerNetworkCallback subscribes to connectivity events so the node
    // re-dials peers when the host network changes. ACCESS_NETWORK_STATE is
    // declared in AndroidManifest.xml (no runtime prompt needed — it is a
    // normal/install-time permission).
    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return
        connectivityManager = cm

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // A new network is usable — schedule a debounced reconnect.
                scheduleReconnect()
            }

            override fun onLost(network: Network) {
                // The current network was lost — schedule a debounced reconnect
                // so the node drops dead peers and re-dials on the next
                // available interface.
                scheduleReconnect()
            }
        }
        networkCallback = callback
        cm.registerNetworkCallback(request, callback)
    }

    private fun scheduleReconnect() {
        // Cancel any pending reconnect and restart the debounce window so
        // rapid transitions (onLost immediately followed by onAvailable) are
        // collapsed into a single call.
        debounceHandler.removeCallbacks(reconnectRunnable)
        debounceHandler.postDelayed(reconnectRunnable, debounceDelayMs)
    }

    private fun handleNetworkChange() {
        // Must NOT run on the main thread: app.onNetworkChanged() performs a
        // node Stop+relaunch which is a blocking, I/O-bound operation.
        Thread {
            try {
                app.onNetworkChanged()
            } catch (e: Exception) {
                android.util.Log.w("bursa", "onNetworkChanged failed", e)
            }
            // Reload the WebView on the main thread after the node has
            // re-dialled so the SPA reconnects to the refreshed control surface.
            runOnUiThread {
                if (this::webView.isInitialized) {
                    webView.reload()
                }
            }
        }.start()
    }

    override fun onDestroy() {
        // Cancel any pending debounced reconnect.
        debounceHandler.removeCallbacks(reconnectRunnable)

        // Unregister the network callback before tearing the wallet down so
        // no late callbacks try to call app.onNetworkChanged() after Stop.
        networkCallback?.let { cb ->
            connectivityManager?.unregisterNetworkCallback(cb)
        }
        networkCallback = null

        // Tear the wallet down: drains the control surface and winds down the
        // in-process node.
        if (this::app.isInitialized) {
            app.stop()
        }
        if (this::webView.isInitialized) {
            webView.destroy()
        }
        super.onDestroy()
    }
}
