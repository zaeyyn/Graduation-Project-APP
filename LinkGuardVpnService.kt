package com.example.myapplication

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream


class LinkGuardVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    companion object {
        const val ACTION_THREAT = "com.example.myapplication.THREAT"
    }

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        vpnInterface = Builder()
            .addAddress("10.0.0.2", 24)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)
            .setSession("LinkGuard")
            .addDisallowedApplication(packageName)
            .establish()

        isRunning = true

        Thread {
            try {
                val buffer = ByteArray(32767)
                val input = FileInputStream(vpnInterface!!.fileDescriptor)
                while (isRunning) {
                    val length = input.read(buffer)
                    if (length > 0) {
                        Log.d("LinkGuard", "Packet received: $length bytes")
                        val domain = extractDomain(buffer, length)
                        if (domain != null) {
                            Log.d("LinkGuard", "Domain: $domain")
                            checkDomain(domain)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.d("LinkGuard", "VPN stopped: ${e.message}")
            }
        }.start()
    }

    private fun checkDomain(domain: String) {
        Thread {
            try {
                val url = java.net.URL("https://linkguard-api-yy7v.onrender.com/check")
                val connection = url.openConnection() as java.net.HttpURLConnection
                connection.requestMethod = "POST"
                connection.setRequestProperty("Content-Type", "application/json")
                connection.doOutput = true
                val body = "{\"url\": \"$domain\"}"
                connection.outputStream.write(body.toByteArray())
                val response = connection.inputStream.bufferedReader().readText()
                Log.d("LinkGuard", "API Response for $domain: $response")
                val json = org.json.JSONObject(response)
                val verdict = json.getString("verdict")
                val intent = android.content.Intent(ACTION_THREAT)
                intent.putExtra("domain", domain)
                intent.putExtra("verdict", verdict)
                sendBroadcast(intent)
                connection.disconnect()
            } catch (e: Exception) {
                Log.d("LinkGuard", "checkDomain error: ${e.message}")

            }
        }.start()
    }

    private fun extractDomain(data: ByteArray, length: Int): String? {
        return try {
            if (length < 40) return null
            var i = 40
            val sb = StringBuilder()
            while (i < length) {
                val labelLen = data[i].toInt() and 0xFF
                if (labelLen == 0) break
                if (sb.isNotEmpty()) sb.append(".")
                i++
                for (j in 0 until labelLen) {
                    if (i + j < length)
                        sb.append(data[i + j].toInt().toChar())
                }
                i += labelLen
            }
            if (sb.isNotEmpty()) sb.toString() else null
        } catch (e: Exception) { null }
    }

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
    }
}