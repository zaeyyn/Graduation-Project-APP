package com.example.myapplication

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.net.HttpURLConnection
import java.net.URL

class LinkGuardVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    // FIXED: @Volatile ensures isRunning is visible across threads immediately
    @Volatile
    private var isRunning = false

    companion object {
        const val ACTION_THREAT = "com.example.myapplication.THREAT"
        private const val TAG = "LinkGuard"
        private const val API_URL = "https://linkguard-api-yy7v.onrender.com/check"
        private const val TIMEOUT_MS = 15_000
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
                        Log.d(TAG, "Packet received: $length bytes")
                        val domain = extractDomain(buffer, length)
                        if (domain != null) {
                            Log.d(TAG, "Domain extracted: $domain")
                            checkDomain(domain)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "VPN thread stopped: ${e.message}")
            }
        }.start()
    }

    private fun checkDomain(domain: String) {
        Thread {
            var connection: HttpURLConnection? = null
            try {
                // FIXED: prepend https:// so the API receives a valid URL
                val fullUrl = if (domain.startsWith("http")) domain else "https://$domain"

                connection = URL(API_URL).openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.setRequestProperty("Content-Type", "application/json")
                connection.doOutput = true
                // FIXED: set timeouts to prevent hanging forever
                connection.connectTimeout = TIMEOUT_MS
                connection.readTimeout = TIMEOUT_MS

                val body = "{\"url\": \"$fullUrl\"}"
                connection.outputStream.use { it.write(body.toByteArray()) }

                val response = connection.inputStream.bufferedReader().readText()
                Log.d(TAG, "API Response for $domain: $response")

                val json = org.json.JSONObject(response)
                val verdict = json.getString("verdict")

                val intent = Intent(ACTION_THREAT)
                intent.putExtra("domain", domain)
                intent.putExtra("verdict", verdict)
                sendBroadcast(intent)

            } catch (e: Exception) {
                // FIXED: use Log.e for errors so they're visible in error filters
                Log.e(TAG, "checkDomain error for $domain: ${e.message}")
            } finally {
                // FIXED: disconnect in finally so it always runs even on exception
                connection?.disconnect()
            }
        }.start()
    }

    private fun extractDomain(data: ByteArray, length: Int): String? {
        return try {
            // Note: offset 40 assumes IPv4 (20 bytes) + UDP (8 bytes) + DNS header (12 bytes)
            // This won't work for TCP or IPv6 packets
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
        } catch (e: Exception) {
            Log.e(TAG, "extractDomain error: ${e.message}")
            null
        }
    }

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
        Log.d(TAG, "VPN service destroyed")
    }
}