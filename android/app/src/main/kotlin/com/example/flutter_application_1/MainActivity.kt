package com.example.flutter_application_1

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    private val channel = "linkguard/vpn"
    private var methodChannel: MethodChannel? = null
    private val VPN_REQUEST_CODE = 100

    // Debounce — same URL won't show danger screen twice within 10 seconds
    private var lastDangerUrl = ""
    private var lastDangerTime = 0L
    private val DANGER_DEBOUNCE_MS = 10_000L

    // Track which danger URL we already showed — prevents onResume re-showing old intents
    private var handledDangerUrl = ""

    // Retry until Flutter is ready — handles both background resume and cold start
    private fun showDangerWhenReady(url: String, score: Double, attempts: Int = 0) {
        if (attempts > 10) return // Give up after 5 seconds
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
                else -> result.notImplemented()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val dangerUrl = intent?.getStringExtra("danger_url") ?: return
        if (intent?.getBooleanExtra("show_danger", false) != true) return
        if (dangerUrl == handledDangerUrl) return // Already showed this — skip
        handledDangerUrl = dangerUrl
        val score = intent?.getDoubleExtra("danger_score", 0.0) ?: 0.0
        showDangerIfNew(dangerUrl, score)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)       // Update current intent to the new one
        handledDangerUrl = ""   // Reset so onResume shows the new danger
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
}