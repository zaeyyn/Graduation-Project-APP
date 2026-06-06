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
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.nio.ByteBuffer

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
            val buffer = ByteArray(32767)
            val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)

            try {
                while (isRunning) {
                    val length = inputStream.read(buffer)
                    if (length <= 0) continue

                    val packet = ByteBuffer.wrap(buffer, 0, length)

                    // Forward packet (pass-through VPN)
                    outputStream.write(buffer, 0, length)

                    // Try to extract DNS query domain
                    val domain = parseDnsQuery(buffer, length)
                    if (domain != null && domain.isNotEmpty() && !domain.startsWith(".")) {
                        Log.d(TAG, "DNS query: $domain")
                        checkDomain(domain)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "VPN thread error: ${e.message}")
            }
        }.start()
    }

    /**
     * Parse DNS query packet to extract the queried domain name.
     * DNS packet structure over UDP/IP:
     * - IP header: 20 bytes (IPv4)
     * - UDP header: 8 bytes
     * - DNS header: 12 bytes
     * - DNS question: variable (domain name + type + class)
     */
    private fun parseDnsQuery(data: ByteArray, length: Int): String? {
        return try {
            // Minimum size: IP(20) + UDP(8) + DNS header(12) = 40 bytes
            if (length < 40) return null

            // Check IP version (first nibble of first byte)
            val ipVersion = (data[0].toInt() and 0xFF) shr 4
            if (ipVersion != 4) return null  // Only IPv4

            // IP header length (second nibble of first byte, in 32-bit words)
            val ipHeaderLen = (data[0].toInt() and 0x0F) * 4
            if (ipHeaderLen < 20) return null

            // Protocol (byte 9 of IP header)
            val protocol = data[9].toInt() and 0xFF
            if (protocol != 17) return null  // Only UDP (17)

            // Check destination port (UDP header starts after IP header)
            val udpOffset = ipHeaderLen
            if (udpOffset + 8 > length) return null

            val destPort = ((data[udpOffset + 2].toInt() and 0xFF) shl 8) or
                    (data[udpOffset + 3].toInt() and 0xFF)
            if (destPort != 53) return null  // Only DNS (port 53)

            // DNS header starts after UDP header
            val dnsOffset = udpOffset + 8
            if (dnsOffset + 12 > length) return null

            // DNS flags (bytes 2-3 of DNS header): QR bit (bit 15) must be 0 for query
            val flags = ((data[dnsOffset + 2].toInt() and 0xFF) shl 8) or
                    (data[dnsOffset + 3].toInt() and 0xFF)
            val isQuery = (flags and 0x8000) == 0
            if (!isQuery) return null

            // Question count (bytes 4-5 of DNS header)
            val questionCount = ((data[dnsOffset + 4].toInt() and 0xFF) shl 8) or
                    (data[dnsOffset + 5].toInt() and 0xFF)
            if (questionCount == 0) return null

            // Parse first question: domain name starts at byte 12 of DNS section
            var pos = dnsOffset + 12
            val domainParts = mutableListOf<String>()

            while (pos < length) {
                val labelLen = data[pos].toInt() and 0xFF
                if (labelLen == 0) break  // End of domain name
                if (labelLen > 63) return null  // Invalid label length
                pos++
                if (pos + labelLen > length) return null
                val label = String(data, pos, labelLen, Charsets.US_ASCII)
                domainParts.add(label)
                pos += labelLen
            }

            if (domainParts.isEmpty()) return null
            domainParts.joinToString(".")

        } catch (e: Exception) {
            null
        }
    }

    private val checkedDomains = mutableMapOf<String, Long>()
    private val CACHE_TTL_MS = 60_000L // 1 minute cache

    private fun checkDomain(domain: String) {
        // Skip system/internal domains
        if (domain.endsWith(".local") ||
            domain.endsWith(".internal") ||
            domain.endsWith(".arpa") ||
            domain.contains("google") && (domain.endsWith(".com") || domain.endsWith(".net")) ||
            domain == "localhost") return

        // Cache check — don't re-check same domain within 1 minute
        val now = System.currentTimeMillis()
        val lastChecked = checkedDomains[domain]
        if (lastChecked != null && (now - lastChecked) < CACHE_TTL_MS) return
        checkedDomains[domain] = now

        // Clean old cache entries
        if (checkedDomains.size > 100) {
            val oldEntries = checkedDomains.filter { (now - it.value) > CACHE_TTL_MS }
            oldEntries.keys.forEach { checkedDomains.remove(it) }
        }

        Thread {
            var connection: HttpURLConnection? = null
            try {
                val fullUrl = "https://$domain"

                connection = URL(API_URL).openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.setRequestProperty("Content-Type", "application/json")
                connection.doOutput = true
                connection.connectTimeout = TIMEOUT_MS
                connection.readTimeout = TIMEOUT_MS

                val body = "{\"url\": \"$fullUrl\"}"
                connection.outputStream.use { it.write(body.toByteArray()) }

                val response = connection.inputStream.bufferedReader().readText()
                Log.d(TAG, "API response for $domain: $response")

                val json = org.json.JSONObject(response)
                val verdict = json.getString("verdict")
                val score = json.optDouble("score", 0.0)

                if (verdict == "DANGER") {
                    Log.d(TAG, "DANGER detected: $domain")
                    showThreatNotification(domain)

                    // Send broadcast to Flutter
                    val intent = Intent(ACTION_THREAT).apply {
                        putExtra("domain", domain)
                        putExtra("verdict", verdict)
                        putExtra("url", fullUrl)
                        putExtra("score", score)
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)

                    // Launch danger screen
                    launchDangerScreen(fullUrl, score)
                }

            } catch (e: Exception) {
                Log.e(TAG, "checkDomain error for $domain: ${e.message}")
            } finally {
                connection?.disconnect()
            }
        }.start()
    }

    private fun launchDangerScreen(url: String, score: Double) {
        try {
            val intent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
                addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK or
                            Intent.FLAG_ACTIVITY_CLEAR_TOP or
                            Intent.FLAG_ACTIVITY_SINGLE_TOP
                )
                putExtra("danger_url", url)
                putExtra("danger_score", score)
                putExtra("show_danger", true)
            }
            intent?.let { startActivity(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch danger screen: ${e.message}")
        }
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

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.d(TAG, "VPN service destroyed")
    }
}