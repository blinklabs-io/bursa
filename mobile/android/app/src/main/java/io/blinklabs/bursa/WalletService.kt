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

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat

import io.blinklabs.bursa.mobile.App
import io.blinklabs.bursa.mobile.Mobile

// WalletService is a bound foreground Service that OWNS the gomobile App (the
// embedded lean Dingo node + loopback control surface). Hosting the wallet in a
// foreground service — rather than in the Activity — keeps the node alive and
// syncing while the app is backgrounded, instead of being torn down with the UI
// and killed by the OS.
//
// The Activity binds to this service to learn the loopback port() and to route
// lifecycle "kicks" (onNetworkChanged / onResume) to the service-held App. The
// ConnectivityManager.NetworkCallback also lives here (not in the Activity) so
// the node re-dials on a network change even while backgrounded.
class WalletService : Service() {

    companion object {
        private const val TAG = "bursa"

        // Notification plumbing. The channel is created in onCreate (it MUST
        // exist before startForeground posts a notification against it).
        private const val CHANNEL_ID = "bursa_sync"
        private const val NOTIFICATION_ID = 1

        // Debounce window for network transitions (e.g. WiFi hand-off to
        // cellular): a 500 ms window collapses back-to-back onLost→onAvailable
        // events from a single interface change into one re-dial.
        private const val DEBOUNCE_DELAY_MS = 500L
    }

    // The booted wallet. Null until started; guarded by the service's single
    // (main) thread for lifecycle transitions. started gates double-start.
    private var app: App? = null
    private var started = false

    private val binder = LocalBinder()

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private val debounceHandler = Handler(Looper.getMainLooper())
    private val reconnectRunnable = Runnable { handleNetworkChange() }

    // LocalBinder is the in-process binding surface. The Activity casts the
    // IBinder it receives in onServiceConnected to this and calls through to the
    // service-held App. All methods are safe before the wallet has started
    // (port() returns 0; the kicks no-op).
    inner class LocalBinder : Binder() {
        // port returns the loopback port the control surface bound, or 0 if the
        // wallet has not finished starting. The Activity polls/loads only once
        // this is non-zero (handles the bind-before-boot race).
        fun port(): Int = app?.port()?.toInt() ?: 0

        // onNetworkChanged / onResume are pass-throughs to the service-held App
        // so the Activity routes its lifecycle kicks to the wallet the service
        // owns. They are blocking, I/O-bound node operations — callers MUST
        // invoke them off the main thread.
        fun onNetworkChanged() {
            app?.onNetworkChanged()
        }

        fun onResume() {
            app?.onResume()
        }
    }

    override fun onCreate() {
        super.onCreate()
        // The channel must exist before any startForeground call posts against
        // it (a missing channel throws on API 26+).
        createNotificationChannel()
    }

    // onStartCommand promotes the service to the foreground and boots the
    // wallet. It is idempotent: a redelivered start intent (or a second
    // startForegroundService from the Activity) must not double-start the node.
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Always (re)assert foreground status with the ongoing notification.
        // On API 29+ the foregroundServiceType MUST be passed here too — it has
        // to match the manifest's android:foregroundServiceType="dataSync".
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                buildNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification())
        }

        startWalletIfNeeded()

        // STICKY: if the OS kills us under memory pressure, restart the service
        // (with a null intent) so the node comes back up. We don't carry intent
        // data, so we don't need REDELIVER_INTENT.
        return START_STICKY
    }

    // startWalletIfNeeded boots the gomobile App once. Guarded by `started` so
    // repeated onStartCommand deliveries don't attempt a second start (the Go
    // side also errors on double-start, but we gate here to avoid the throw).
    private fun startWalletIfNeeded() {
        if (started) return
        val instance = Mobile.new_()
        try {
            // filesDir = app-private writable dir; "preview" network; lean=true
            // selects the small-footprint history-expiry profile for a phone.
            instance.start(filesDir.absolutePath, "preview", true)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "wallet start failed", e)
            // Could not boot — drop foreground status and stop. The Activity's
            // binder.port() will keep returning 0 and it will not load a dead
            // port.
            stopSelf()
            return
        }
        app = instance
        started = true

        // Now that the node is running, watch for host network changes so it
        // re-dials peers even while the Activity is gone/backgrounded.
        registerNetworkCallback()
    }

    // registerNetworkCallback subscribes to connectivity events. Lives in the
    // service (moved out of the Activity in F2) so re-dial works while
    // backgrounded. ACCESS_NETWORK_STATE is a normal/install-time permission.
    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return
        connectivityManager = cm

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                scheduleReconnect()
            }

            override fun onLost(network: Network) {
                scheduleReconnect()
            }
        }
        networkCallback = callback
        cm.registerNetworkCallback(request, callback)
    }

    private fun scheduleReconnect() {
        // Restart the debounce window so rapid onLost→onAvailable transitions
        // collapse into a single reconnect.
        debounceHandler.removeCallbacks(reconnectRunnable)
        debounceHandler.postDelayed(reconnectRunnable, DEBOUNCE_DELAY_MS)
    }

    private fun handleNetworkChange() {
        // onNetworkChanged performs a node Stop+relaunch — blocking, I/O-bound —
        // so it MUST NOT run on the main thread.
        val instance = app ?: return
        Thread {
            try {
                instance.onNetworkChanged()
            } catch (e: Exception) {
                android.util.Log.w(TAG, "onNetworkChanged failed", e)
            }
        }.start()
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        // Cancel any pending debounced reconnect.
        debounceHandler.removeCallbacks(reconnectRunnable)

        // Unregister the network callback before tearing the wallet down so no
        // late callback tries to call onNetworkChanged() after Stop.
        networkCallback?.let { cb ->
            connectivityManager?.unregisterNetworkCallback(cb)
        }
        networkCallback = null

        // Wind down the in-process node and drain the control surface.
        app?.stop()
        app = null
        started = false
        super.onDestroy()
    }

    // createNotificationChannel registers the low-importance channel used for
    // the ongoing "syncing" notification. No-op before API 26 (channels did not
    // exist then). IMPORTANCE_LOW => no sound, collapsed by default.
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.sync_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.sync_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    // buildNotification creates the ongoing, low-priority "Bursa is syncing"
    // notification shown while the service runs. Tapping it returns to the app.
    private fun buildNotification(): Notification {
        val contentIntent = android.app.PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            android.app.PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.sync_notification_title))
            .setContentText(getString(R.string.sync_notification_text))
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setShowWhen(false)
            .setContentIntent(contentIntent)
            .build()
    }
}
