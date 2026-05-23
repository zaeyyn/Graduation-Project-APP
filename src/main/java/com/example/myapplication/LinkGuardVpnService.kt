package com.example.myapplication

import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.json.JSONObject
import java.io.FileInputStream

class LinkGuardVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

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
                val url = java.net.URL("https://graduation-project-app-production.up.railway.app/check")
                val connection = url.openConnection() as java.net.HttpURLConnection
                connection.requestMethod = "POST"
                connection.setRequestProperty("Content-Type", "application/json")
                connection.doOutput = true

                val body = "{\"url\": \"$domain\"}"
                connection.outputStream.write(body.toByteArray())

                val response = connection.inputStream.bufferedReader().readText()
                Log.d("LinkGuard", "API Response for $domain: $response")
                connection.disconnect()

                // Parse verdict and Arabic message from response
                val json = JSONObject(response)
                val verdict   = json.optString("verdict", "SAFE")
                val messageAr = json.optString("message_ar", "تم اكتشاف رابط خطير: $domain")

                if (verdict == "DANGER") {
                    showNotification(domain, messageAr)
                }

            } catch (e: Exception) {
                Log.d("LinkGuard", "checkDomain error: ${e.message}")
            }
        }.start()
    }

    private fun showNotification(domain: String, messageAr: String) {
        val channelId = "linkguard_alerts"

        // Create notification channel (required for Android 8+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "LinkGuard Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Dangerous link alerts"
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("⚠️ رابط خطير")
            .setContentText(messageAr)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(this).notify(domain.hashCode(), notification)
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
