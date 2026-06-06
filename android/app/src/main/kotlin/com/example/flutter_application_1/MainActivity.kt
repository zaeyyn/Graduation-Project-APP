package com.example.flutter_application_1

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    private val channel = "linkguard/vpn"
    private var methodChannel: MethodChannel? = null
    private val VPN_REQUEST_CODE = 100

    // Debounce — prevent same URL from showing danger screen twice within 10 seconds
    private var lastDangerUrl = ""
    private var lastDangerTime = 0L
    private val DANGER_DEBOUNCE_MS = 10_000L

    private fun showDangerIfNew(url: String, score: Double) {
        val now = System.currentTimeMillis()
        if (url == lastDangerUrl && (now - lastDangerTime) < DANGER_DEBOUNCE_MS) return
        lastDangerUrl = url
        lastDangerTime = now
        runOnUiThread {
            methodChannel?.invokeMethod(
                "showDangerScreen", mapOf("url" to url, "score" to score)
            )
        }
    }

    // Receives DANGER broadcast from VPN service
    private val threatReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val url = intent?.getStringExtra("url") ?: return
            val score = intent.getDoubleExtra("score", 0.0)
            showDangerIfNew(url, score)
        }
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

        // Listen for DANGER broadcasts from VPN service
        val filter = IntentFilter(LinkGuardVpnService.ACTION_THREAT)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(threatReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(threatReceiver, filter)
        }

        // Handle danger intent if app was launched from accessibility service
        handleDangerIntent(intent)
    }

    // Called when user accepts or denies VPN permission dialog
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

    // Called when accessibility service launches danger screen via intent
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDangerIntent(intent)
    }

    // Handles danger screen from accessibility service intent
    private fun handleDangerIntent(intent: Intent?) {
        if (intent?.getBooleanExtra("show_danger", false) == true) {
            val url = intent.getStringExtra("danger_url") ?: return
            val score = intent.getDoubleExtra("danger_score", 0.0)
            showDangerIfNew(url, score)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(threatReceiver)
    }
}