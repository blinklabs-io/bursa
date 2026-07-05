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

import android.Manifest
import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.ViewGroup
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

// MainActivity no longer owns the wallet. The embedded node + loopback control
// surface live in WalletService (a foreground Service) so they survive the
// Activity being backgrounded/destroyed. MainActivity starts that service,
// binds to it, reads the loopback port() from the binder once the wallet has
// booted, and points a full-screen WebView at it.
//
// The ConnectivityManager.NetworkCallback (F2) lives in the service now; the
// onResume threshold logic (F3) stays here but routes its heavy re-dial to the
// bound service-held App.
class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView

    // Binder to the wallet service. Non-null only while bound.
    private var walletBinder: WalletService.LocalBinder? = null
    private var bindRequested = false
    private var bound = false

    // Resume-threshold (F3): only trigger a full OnResume re-dial when the app
    // has been backgrounded longer than this. Quick app-switches (permission
    // prompts, recent-apps gestures) do not bounce the node.
    private val resumeThresholdMs = 30_000L
    private var pauseTimestampMs = 0L

    // The wallet boots asynchronously inside the service, so the port may be 0
    // for a moment after we bind. We poll the binder until it reports a non-zero
    // port, then load the WebView (handles the bind-before-boot race).
    private val mainHandler = Handler(Looper.getMainLooper())
    private val portPollDelayMs = 100L
    private var webViewLoaded = false
    private var walletPort = 0

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            walletBinder = service as? WalletService.LocalBinder
            bound = true
            // The wallet may still be booting; wait for a real port.
            loadWebViewWhenReady()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            // The service process went away (e.g. crash). Drop the binder; the
            // system will rebind when it returns.
            walletBinder = null
            bound = false
        }
    }

    // Runtime POST_NOTIFICATIONS request (Android 13+). The result is ignored:
    // the service still runs and the notification still posts whether or not the
    // user grants it — denial only suppresses the visible notification.
    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* granted: Boolean — intentionally ignored */ }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        maybeRequestNotificationPermission()

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            // The SPA talks to the same loopback origin, so no cross-origin or
            // file-access surface is needed.
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    val uri = request.url
                    if (isWalletHttp(uri)) return false
                    showBootError("Blocked navigation to ${uri.host ?: uri}")
                    return true
                }

                override fun onReceivedError(
                    view: WebView,
                    request: WebResourceRequest,
                    error: WebResourceError,
                ) {
                    if (request.isForMainFrame) {
                        showBootError(error.description?.toString() ?: "Page failed to load.")
                    }
                }

                override fun onReceivedHttpError(
                    view: WebView,
                    request: WebResourceRequest,
                    errorResponse: WebResourceResponse,
                ) {
                    if (request.isForMainFrame) {
                        showBootError("Page failed to load (${errorResponse.statusCode}).")
                    }
                }
            }
        }
        setContentView(webView)

        // Start the wallet as a foreground service so it keeps running even when
        // this Activity is backgrounded or destroyed, then bind to read its
        // loopback port. startForegroundService promotes the service to the
        // foreground (it calls startForeground within the required window).
        val intent = Intent(this, WalletService::class.java)
        ContextCompat.startForegroundService(this, intent)
        if (bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            bindRequested = true
        } else {
            showBootError(getString(R.string.wallet_service_bind_failed))
            stopService(intent)
        }
    }

    // maybeRequestNotificationPermission asks for POST_NOTIFICATIONS on API 33+.
    // On older versions the permission is granted at install time and no prompt
    // is needed. The foreground service runs regardless of the answer.
    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun isWalletHttp(uri: Uri): Boolean {
        val host = uri.host ?: return false
        val port = walletPort
        return uri.scheme == "http" &&
            port > 0 &&
            uri.port == port &&
            (host == "127.0.0.1" || host == "localhost" || host == "::1")
    }

    // loadWebViewWhenReady loads the WebView once the bound service reports a
    // non-zero loopback port. If the wallet is still booting (port == 0) it
    // re-polls on the main thread. Idempotent: loads at most once.
    private fun loadWebViewWhenReady() {
        if (webViewLoaded) return

        // Check for a terminal boot failure first. If the node could not start,
        // port() would stay 0 forever and we'd poll indefinitely behind a blank
        // WebView. Surface the error and STOP polling (don't re-post).
        val bootError = walletBinder?.bootError()
        if (bootError != null) {
            showBootError(bootError)
            return
        }

        val port = walletBinder?.port() ?: 0
        if (port == 0) {
            // Still booting (or briefly unbound) — try again shortly.
            if (bound) {
                mainHandler.postDelayed({ loadWebViewWhenReady() }, portPollDelayMs)
            }
            return
        }
        webViewLoaded = true
        walletPort = port
        webView.loadUrl("http://127.0.0.1:$port/")
    }

    // showBootError renders a minimal inline error page when the node fails to
    // boot, replacing the blank WebView the user would otherwise stare at. Marks
    // webViewLoaded so onResume's reload() and the poll loop both treat this as
    // the terminal loaded state.
    private fun showBootError(message: String) {
        webViewLoaded = true
        val escaped = android.text.TextUtils.htmlEncode(message)
        val html = """
            <!doctype html>
            <html><head><meta name="viewport" content="width=device-width,initial-scale=1">
            <style>
              body{font-family:sans-serif;margin:0;padding:24px;background:#111;color:#eee;
                   display:flex;flex-direction:column;justify-content:center;min-height:100vh}
              h1{font-size:1.25rem;margin:0 0 12px}
              p{margin:0;color:#bbb;line-height:1.5;word-break:break-word}
            </style></head>
            <body>
              <h1>Wallet failed to start</h1>
              <p>$escaped</p>
            </body></html>
        """.trimIndent()
        webView.loadDataWithBaseURL(null, html, "text/html", "utf-8", null)
    }

    // onPause records when the app left the foreground so onResume can compute
    // how long it was backgrounded.
    override fun onPause() {
        super.onPause()
        pauseTimestampMs = System.currentTimeMillis()
    }

    // onResume (F3): on becoming visible again, always do the cheap WebView
    // reload so the SPA refetches, and only route a heavy app.onResume() re-dial
    // to the service when the app was suspended longer than the threshold.
    override fun onResume() {
        super.onResume()

        // Always do the lightweight WebView reload so the SPA refetches — but
        // only once it has actually loaded a URL (avoid reloading about:blank
        // before the first load).
        if (webViewLoaded) {
            webView.reload()
        }

        // Skip the heavy re-dial if the suspension was shorter than the
        // threshold (quick app-switch handled by the reload alone).
        val elapsed = if (pauseTimestampMs > 0) System.currentTimeMillis() - pauseTimestampMs else 0L
        if (elapsed < resumeThresholdMs) return

        // Route the re-dial to the service-held App. The service serializes
        // the heavy node Stop+relaunch work off this thread.
        val binder = walletBinder ?: return
        binder.onResume()
    }

    override fun onDestroy() {
        // Stop polling for the port.
        mainHandler.removeCallbacksAndMessages(null)

        // Unbind from — but do NOT stop — the service: the whole point is that
        // the node keeps running (and syncing) after the Activity is gone. The
        // system manages the foreground service's lifetime from here.
        if (bindRequested || bound) {
            try {
                unbindService(connection)
            } catch (e: IllegalArgumentException) {
            }
            bindRequested = false
            bound = false
        }
        walletBinder = null

        if (this::webView.isInitialized) {
            (webView.parent as? ViewGroup)?.removeView(webView)
            webView.destroy()
        }
        super.onDestroy()
    }
}
