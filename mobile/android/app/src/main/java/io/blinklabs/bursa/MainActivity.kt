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
package io.blinklabs.bursa

import android.annotation.SuppressLint
import android.os.Bundle
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
    }

    override fun onDestroy() {
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
