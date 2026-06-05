package com.example.flutter_application_1

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

    private val urlReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val url = intent?.getStringExtra("url") ?: return
            runOnUiThread {
                methodChannel?.invokeMethod("onUrlDetected", url)
            }
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channel)
        methodChannel?.setMethodCallHandler { call, result ->
            when (call.method) {
                "startVpn" -> {
                    val intent = VpnService.prepare(this)
                    if (intent != null) {
                        startActivityForResult(intent, 0)
                    } else {
                        startService(Intent(this, LinkGuardVpnService::class.java))
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

        // Listen for URLs detected by accessibility service
        val filter = IntentFilter(LinkGuardAccessibilityService.ACTION_URL_DETECTED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(urlReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(urlReceiver, filter)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(urlReceiver)
    }
}