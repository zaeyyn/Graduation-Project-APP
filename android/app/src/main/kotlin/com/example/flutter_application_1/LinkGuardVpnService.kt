package com.example.flutter_application_1

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.net.HttpURLConnection
import java.net.URL

class LinkGuardVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    @Volatile
    private var isRunning = false

    companion object {
        const val ACTION_THREAT = "com.example.flutter_application_1.THREAT"
        private const val TAG = "LinkGuard"
        private const val API_URL = "https://linkguard-api-yy7v.onrender.com/check"
        private const val TIMEOUT_MS = 15_000
        private const val CHANNEL_ID = "linkguard_channel"
        private const val NOTIFICATION_ID = 1
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        startVpn()
        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "LinkGuard Protection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "LinkGuard VPN protection status"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val openAppIntent = packageManager
            .getLaunchIntentForPackage(packageName)
            ?.let { PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE) }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("LinkGuard Active")
            .setContentText("Protecting your links in the background")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(openAppIntent)
            .build()
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
                val fullUrl = if (domain.startsWith("http")) domain else "https://$domain"

                connection = URL(API_URL).openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.setRequestProperty("Content-Type", "application/json")
                connection.doOutput = true
                connection.connectTimeout = TIMEOUT_MS
                connection.readTimeout = TIMEOUT_MS

                val body = "{\"url\": \"$fullUrl\"}"
                connection.outputStream.use { it.write(body.toByteArray()) }

                val response = connection.inputStream.bufferedReader().readText()
                Log.d(TAG, "API Response for $domain: $response")

                val json = org.json.JSONObject(response)
                val verdict = json.getString("verdict")

                if (verdict == "DANGER") {
                    showThreatNotification(domain)
                }

                val intent = Intent(ACTION_THREAT)
                intent.putExtra("domain", domain)
                intent.putExtra("verdict", verdict)
                sendBroadcast(intent)

            } catch (e: Exception) {
                Log.e(TAG, "checkDomain error for $domain: ${e.message}")
            } finally {
                connection?.disconnect()
            }
        }.start()
    }

    private fun showThreatNotification(domain: String) {
        val openAppIntent = packageManager
            .getLaunchIntentForPackage(packageName)
            ?.let { PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE) }

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("⚠️ Dangerous Link Blocked!")
            .setContentText("$domain was blocked for your safety")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(openAppIntent)
            .build()

        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID + 1, notification)
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
        } catch (e: Exception) {
            Log.e(TAG, "extractDomain error: ${e.message}")
            null
        }
    }

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.d(TAG, "VPN service destroyed")
    }
}