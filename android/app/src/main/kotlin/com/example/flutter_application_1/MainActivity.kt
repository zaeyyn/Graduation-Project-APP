package com.example.flutter_application_1

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    private val channel = "linkguard/vpn"
    private var methodChannel: MethodChannel? = null
    private val VPN_REQUEST_CODE = 100

    // Danger screen debounce
    private var lastDangerUrl = ""
    private var lastDangerTime = 0L
    private val DANGER_DEBOUNCE_MS = 10_000L
    private var handledDangerUrl = ""

    // Pending link history entries when app is in background
    private val pendingLinks = mutableListOf<Map<String, Any>>()

    // Receives ALL link check results from VPN — saves to history + updates counters
    private val linkCheckedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val url = intent?.getStringExtra("url") ?: return
            val verdict = intent.getStringExtra("verdict") ?: return
            val score = intent.getDoubleExtra("score", 0.0)
            val data = mapOf<String, Any>("url" to url, "verdict" to verdict, "score" to score)

            if (methodChannel != null) {
                runOnUiThread {
                    methodChannel?.invokeMethod("onLinkChecked", data)
                }
            } else {
                // App in background — store and process when app opens
                synchronized(pendingLinks) { pendingLinks.add(data) }
            }
        }
    }

    private fun showDangerWhenReady(url: String, score: Double, attempts: Int = 0) {
        if (attempts > 10) return
        if (methodChannel == null) {
            window.decorView.postDelayed({
                showDangerWhenReady(url, score, attempts + 1)
            }, 500)
            return
        }
        runOnUiThread {
            methodChannel?.invokeMethod(
                "showDangerScreen", mapOf("url" to url, "score" to score)
            )
        }
    }

    private fun showDangerIfNew(url: String, score: Double) {
        val now = System.currentTimeMillis()
        if (url == lastDangerUrl && (now - lastDangerTime) < DANGER_DEBOUNCE_MS) return
        lastDangerUrl = url
        lastDangerTime = now
        showDangerWhenReady(url, score)
    }

    // Checks Android's actual active network transport rather than trusting
    // any cached flag, so it stays correct even after the app process was
    // killed and restarted while the VPN kept running in the background.
    private fun isVpnActive(): Boolean {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return false
        val capabilities = cm.getNetworkCapabilities(network) ?: return false
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        methodChannel = MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger, channel
        )

        methodChannel?.setMethodCallHandler { call, result ->
            when (call.method) {
                "startVpn" -> {
                    val vpnIntent = VpnService.prepare(this)
                    if (vpnIntent != null) {
                        startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
                    } else {
                        startVpnService()
                    }
                    result.success(null)
                }
                "stopVpn" -> {
                    stopService(Intent(this, LinkGuardVpnService::class.java))
                    result.success(null)
                }
                "isVpnActive" -> {
                    result.success(isVpnActive())
                }
                else -> result.notImplemented()
            }
        }

        // Register receiver for ALL link check results
        val linkFilter = IntentFilter(LinkGuardVpnService.ACTION_LINK_CHECKED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(linkCheckedReceiver, linkFilter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(linkCheckedReceiver, linkFilter)
        }
    }

    override fun onResume() {
        super.onResume()

        // Process any pending link history entries
        synchronized(pendingLinks) {
            if (pendingLinks.isNotEmpty() && methodChannel != null) {
                val toProcess = pendingLinks.toList()
                pendingLinks.clear()
                runOnUiThread {
                    for (data in toProcess) {
                        methodChannel?.invokeMethod("onLinkChecked", data)
                    }
                }
            }
        }

        // Show danger screen if launched with danger intent
        val dangerUrl = intent?.getStringExtra("danger_url") ?: return
        if (intent?.getBooleanExtra("show_danger", false) != true) return
        if (dangerUrl == handledDangerUrl) return
        handledDangerUrl = dangerUrl
        val score = intent?.getDoubleExtra("danger_score", 0.0) ?: 0.0
        showDangerIfNew(dangerUrl, score)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handledDangerUrl = ""
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                startVpnService()
            } else {
                runOnUiThread {
                    methodChannel?.invokeMethod("onVpnDenied", null)
                }
            }
        }
    }

    private fun startVpnService() {
        val serviceIntent = Intent(this, LinkGuardVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(linkCheckedReceiver)
    }
}