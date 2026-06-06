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
        private const val CACHE_TTL_MS = 300_000L // 5 minutes
    }

    // Domains/suffixes to NEVER send to API — skip immediately in VPN thread
    private val SKIP_SUFFIXES = listOf(
        ".google.com", ".googleapis.com", ".gstatic.com",
        ".googleusercontent.com", ".googlevideo.com",
        ".facebook.com", ".fbcdn.net", ".facebook.net",
        ".whatsapp.com", ".whatsapp.net",
        ".instagram.com", ".cdninstagram.com",
        ".apple.com", ".icloud.com", ".mzstatic.com",
        ".microsoft.com", ".microsoftonline.com",
        ".windows.com", ".live.com", ".msftconnecttest.com",
        ".samsung.com", ".samsungcloud.com",
        ".android.com",
        ".amazon.com", ".amazonaws.com", ".cloudfront.net",
        ".akamaized.net", ".akamai.net", ".fastly.net",
        ".cloudflare.com", ".edgesuite.net",
        ".pool.ntp.org", ".ntp.org",
        ".spotify.com", ".netflix.com",
        ".twitter.com", ".x.com", ".linkedin.com",
        ".youtube.com", ".gmail.com", ".wikipedia.org"
    )

    private val SKIP_EXACT = setOf(
        "dns.google", "localhost",
        "connectivitycheck.gstatic.com",
        "detectportal.firefox.com"
    )

    private fun shouldSkipDomain(domain: String): Boolean {
        if (domain in SKIP_EXACT) return true
        if (domain.endsWith(".local") ||
            domain.endsWith(".arpa") ||
            domain.endsWith(".internal")) return true
        for (suffix in SKIP_SUFFIXES) {
            if (domain.endsWith(suffix) || domain == suffix.trimStart('.')) return true
        }
        return false
    }

    private val checkedDomains = mutableMapOf<String, Long>()

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
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
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

                    // Forward packet immediately
                    outputStream.write(buffer, 0, length)

                    val domain = parseDnsQuery(buffer, length) ?: continue
                    if (domain.isEmpty() || domain.startsWith(".")) continue

                    // Skip known-safe infrastructure in VPN thread — no API call
                    if (shouldSkipDomain(domain)) continue

                    Log.d(TAG, "DNS query: $domain")
                    checkDomain(domain)
                }
            } catch (e: Exception) {
                Log.e(TAG, "VPN thread error: ${e.message}")
            }
        }.start()
    }

    private fun parseDnsQuery(data: ByteArray, length: Int): String? {
        return try {
            if (length < 40) return null
            val ipVersion = (data[0].toInt() and 0xFF) shr 4
            if (ipVersion != 4) return null
            val ipHeaderLen = (data[0].toInt() and 0x0F) * 4
            if (ipHeaderLen < 20) return null
            val protocol = data[9].toInt() and 0xFF
            if (protocol != 17) return null
            val udpOffset = ipHeaderLen
            if (udpOffset + 8 > length) return null
            val destPort = ((data[udpOffset + 2].toInt() and 0xFF) shl 8) or
                    (data[udpOffset + 3].toInt() and 0xFF)
            if (destPort != 53) return null
            val dnsOffset = udpOffset + 8
            if (dnsOffset + 12 > length) return null
            val flags = ((data[dnsOffset + 2].toInt() and 0xFF) shl 8) or
                    (data[dnsOffset + 3].toInt() and 0xFF)
            if ((flags and 0x8000) != 0) return null
            val questionCount = ((data[dnsOffset + 4].toInt() and 0xFF) shl 8) or
                    (data[dnsOffset + 5].toInt() and 0xFF)
            if (questionCount == 0) return null
            var pos = dnsOffset + 12
            val domainParts = mutableListOf<String>()
            while (pos < length) {
                val labelLen = data[pos].toInt() and 0xFF
                if (labelLen == 0) break
                if (labelLen > 63) return null
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

    private fun checkDomain(domain: String) {
        val now = System.currentTimeMillis()

        // Cache check — 5 minute TTL
        synchronized(checkedDomains) {
            val lastChecked = checkedDomains[domain]
            if (lastChecked != null && (now - lastChecked) < CACHE_TTL_MS) return
            checkedDomains[domain] = now
            if (checkedDomains.size > 200) {
                checkedDomains.entries.removeIf { (now - it.value) > CACHE_TTL_MS }
            }
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
                connection.outputStream.use {
                    it.write("{\"url\": \"$fullUrl\"}".toByteArray())
                }

                val response = connection.inputStream.bufferedReader().readText()
                Log.d(TAG, "API response for $domain: $response")

                val json = org.json.JSONObject(response)
                val verdict = json.getString("verdict")
                val score = json.optDouble("score", 0.0)

                if (verdict == "DANGER") {
                    Log.d(TAG, "DANGER detected: $domain")

                    // Show notification
                    showThreatNotification(domain)

                    // Send broadcast to MainActivity — it handles the danger screen
                    val broadcastIntent = Intent(ACTION_THREAT).apply {
                        putExtra("domain", domain)
                        putExtra("verdict", verdict)
                        putExtra("url", fullUrl)
                        putExtra("score", score)
                        setPackage(packageName)
                    }
                    sendBroadcast(broadcastIntent)
                }

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

        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID + 1, notification)
    }

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.d(TAG, "VPN service destroyed")
    }
}