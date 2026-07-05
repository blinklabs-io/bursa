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
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

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

    // The booted wallet. Null until started; guarded by walletLock because
    // binder calls, connectivity callbacks, and service teardown can arrive on
    // different threads. started gates double-start.
    private val walletLock = Any()
    private val walletExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "bursa-wallet-lifecycle")
    }
    @Volatile
    private var shuttingDown = false
    private var reconnectInFlight = false
    private var app: App? = null
    private var started = false

    // Set to the failure message when the node could not boot (app.start threw).
    // The service keeps its binder answering so the Activity can read this and
    // surface the failure instead of polling port() forever. Guarded by
    // walletLock like the other lifecycle state.
    private var bootError: String? = null

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
        fun port(): Int = synchronized(walletLock) {
            app?.port()?.toInt() ?: 0
        }

        // bootError returns the node boot-failure message, or null if the wallet
        // has not failed (still booting, or booted fine). The Activity checks
        // this each poll so a boot failure ends the poll loop and surfaces an
        // error instead of waiting on a port that will never arrive.
        fun bootError(): String? = synchronized(walletLock) {
            this@WalletService.bootError
        }

        // onNetworkChanged / onResume enqueue serialized service-held App kicks.
        // The Go side performs a node Stop+relaunch cycle, so only one lifecycle
        // kick may run at a time and none may overlap service teardown.
        fun onNetworkChanged() {
            enqueueWalletKick("onNetworkChanged") { it.onNetworkChanged() }
        }

        fun onResume() {
            enqueueWalletKick("onResume") { it.onResume() }
        }
    }

    override fun onCreate() {
        super.onCreate()
        // The channel must exist before any startForeground call posts against
        // it (a missing channel throws on API 26+).
        createNotificationChannel()
    }

    // onStartCommand promotes the service to the foreground and dispatches the
    // wallet boot off the service thread. It is idempotent: a redelivered start
    // intent (or a second startForegroundService from the Activity) must not
    // double-start the node.
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Always (re)assert foreground status with the ongoing notification.
        // On API 29+ the foregroundServiceType MUST be passed here too — it has
        // to match the manifest's android:foregroundServiceType="dataSync"
        // (which itself is a required manifest declaration as of API 34).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                buildNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification())
        }

        try {
            walletExecutor.execute { startWalletIfNeeded() }
        } catch (e: RejectedExecutionException) {
            android.util.Log.w(TAG, "wallet start rejected", e)
        }

        // STICKY: if the OS kills us under memory pressure, restart the service
        // (with a null intent) so the node comes back up. We don't carry intent
        // data, so we don't need REDELIVER_INTENT.
        return START_STICKY
    }

    // startWalletIfNeeded boots the gomobile App once. Guarded by `started` so
    // repeated onStartCommand deliveries don't attempt a second start (the Go
    // side also errors on double-start, but we gate here to avoid the throw).
    // A boot failure is also terminal — once `bootError` is set we don't retry.
    private fun startWalletIfNeeded() {
        synchronized(walletLock) {
            if (started || bootError != null || shuttingDown) return
        }
        val instance = Mobile.new_()
        try {
            // filesDir = app-private writable dir; "preview" network; lean=true
            // selects the small-footprint history-expiry profile for a phone.
            instance.start(filesDir.absolutePath, "preview", true)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "wallet start failed", e)
            // Could not boot. We must NOT silently stopSelf() here: the Activity
            // is still bound and only learns of a dead node by polling port(),
            // which would stay 0 forever (onServiceDisconnected does not fire on
            // a stopSelf of a still-bound service). Instead, record the failure
            // so the binder can report it, then drop the foreground notification
            // (there is nothing syncing). Keep the service alive/bound so the
            // Activity can read bootError() and surface it; the system tears the
            // service down once the Activity unbinds in onDestroy.
            synchronized(walletLock) {
                bootError = e.message ?: e.toString()
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
            return
        }
        var stopStartedInstance = false
        synchronized(walletLock) {
            if (shuttingDown) {
                stopStartedInstance = true
            } else {
                app = instance
                started = true
            }
        }
        if (stopStartedInstance) {
            instance.stop()
            return
        }

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
        enqueueWalletKick("onNetworkChanged") { it.onNetworkChanged() }
    }

    private fun enqueueWalletKick(label: String, action: (App) -> Unit) {
        if (shuttingDown) return
        synchronized(walletLock) {
            if (shuttingDown || app == null || reconnectInFlight) return
            reconnectInFlight = true
        }
        try {
            walletExecutor.execute {
                // Grab the instance under the lock, then release it before making
                // the blocking Go call (a node Stop+relaunch, which takes seconds).
                // Holding walletLock for that whole call would also block the
                // binder's port()/bootError() queries and onDestroy() if they run
                // on the main thread concurrently, risking an ANR. The Go side
                // (supervisor.lifecycleMu) already serializes Stop against
                // Reconnect/OnResume, so running action() on this reference after
                // a concurrent onDestroy()/Stop() is safe.
                val instance = synchronized(walletLock) {
                    if (shuttingDown) null else app
                }
                try {
                    instance?.let { action(it) }
                } catch (e: Exception) {
                    android.util.Log.w(TAG, "$label failed", e)
                } finally {
                    synchronized(walletLock) {
                        reconnectInFlight = false
                    }
                }
            }
        } catch (e: RejectedExecutionException) {
            synchronized(walletLock) {
                reconnectInFlight = false
            }
            android.util.Log.w(TAG, "$label rejected", e)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        shuttingDown = true

        // Cancel any pending debounced reconnect.
        debounceHandler.removeCallbacks(reconnectRunnable)

        // Unregister the network callback before tearing the wallet down so no
        // late callback tries to call onNetworkChanged() after Stop.
        networkCallback?.let { cb ->
            connectivityManager?.unregisterNetworkCallback(cb)
        }
        networkCallback = null

        // Wind down the in-process node and drain the control surface. Taking
        // walletLock waits for any in-flight reconnect/resume kick to finish
        // before Stop runs against the same Go App instance.
        val instance = synchronized(walletLock) {
            val current = app
            app = null
            started = false
            reconnectInFlight = false
            current
        }
        instance?.stop()
        walletExecutor.shutdownNow()
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
