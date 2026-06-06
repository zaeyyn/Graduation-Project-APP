package com.example.flutter_application_1

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat
import java.net.HttpURLConnection
import java.net.URL

class LinkGuardAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "LinkGuardAccessibility"
        private const val API_URL = "https://linkguard-api-yy7v.onrender.com/check"
        private const val CHANNEL_ID = "linkguard_channel"
        private const val TIMEOUT_MS = 15_000
    }

    private val recentlyChecked = mutableSetOf<String>()
    private var lastCleanup = System.currentTimeMillis()

    // Only browsers — so WhatsApp never triggers false alarms
    private val browsers = listOf(
        "com.android.chrome",
        "org.mozilla.firefox",
        "com.sec.android.app.sbrowser",
        "com.opera.browser",
        "com.microsoft.emmx",
        "com.brave.browser",
        "com.UCMobile.intl"
    )

    override fun onServiceConnected() {
        super.onServiceConnected()
        val info = AccessibilityServiceInfo().apply {
            // Listen to window opens AND content changes — both needed for Chrome URL bar
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or
                    AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                    AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            notificationTimeout = 100
        }
        serviceInfo = info
        createNotificationChannel()
        Log.d(TAG, "Accessibility service connected")
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "LinkGuard Protection",
                NotificationManager.IMPORTANCE_HIGH
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        val pkg = event.packageName?.toString() ?: return

        // Skip our own app
        if (pkg == packageName) return

        // Only care about browsers — WhatsApp excluded entirely
        if (browsers.none { pkg.contains(it) || it.contains(pkg) }) return

        try {
            // Try event text first (fastest)
            event.text?.forEach { text ->
                val url = extractUrl(text?.toString() ?: "")
                if (url != null) {
                    Log.d(TAG, "URL from event text: $url | pkg=$pkg")
                    handleDetectedUrl(url)
                    return
                }
            }

            // Try node tree (catches URL bar content)
            val source = event.source
            if (source != null) {
                val url = findUrlInNode(source)
                if (url != null) {
                    Log.d(TAG, "URL from node: $url | pkg=$pkg")
                    handleDetectedUrl(url)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error: ${e.message}")
        }
    }

    private fun findUrlInNode(node: AccessibilityNodeInfo): String? {
        try {
            val text = node.text?.toString() ?: ""
            val url = extractUrl(text)
            if (url != null) return url

            val contentDesc = node.contentDescription?.toString() ?: ""
            val urlFromDesc = extractUrl(contentDesc)
            if (urlFromDesc != null) return urlFromDesc

            for (i in 0 until node.childCount) {
                val child = node.getChild(i) ?: continue
                val childUrl = findUrlInNode(child)
                child.recycle()
                if (childUrl != null) return childUrl
            }
        } catch (e: Exception) {
            Log.e(TAG, "findUrlInNode error: ${e.message}")
        }
        return null
    }

    private fun extractUrl(text: String): String? {
        if (text.isBlank()) return null
        val urlRegex = Regex("""https?://[^\s<>"{}|\\^`\[\]]+""")
        return urlRegex.find(text)?.value
    }

    private fun handleDetectedUrl(url: String) {
        val now = System.currentTimeMillis()

        // Clean up every 30 seconds
        if (now - lastCleanup > 30_000) {
            recentlyChecked.clear()
            lastCleanup = now
        }

        // Skip same URL within 10-second window
        val key = "$url:${now / 10_000}"
        if (recentlyChecked.contains(key)) return
        recentlyChecked.add(key)

        Log.d(TAG, "Checking URL: $url")
        Thread {
            checkUrl(url)
        }.start()
    }

    private fun checkUrl(url: String) {
        var connection: HttpURLConnection? = null
        try {
            connection = URL(API_URL).openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.doOutput = true
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS

            val body = "{\"url\": \"$url\"}"
            connection.outputStream.use { it.write(body.toByteArray()) }

            val response = connection.inputStream.bufferedReader().readText()
            Log.d(TAG, "API response: $response")

            val json = org.json.JSONObject(response)
            val verdict = json.getString("verdict")
            val score = json.optDouble("score", 0.0)
            val messageEn = json.optString("message_en", "This link is dangerous.")

            if (verdict == "DANGER") {
                Log.d(TAG, "DANGER: $url")
                showDangerNotification(url, score, messageEn)
                launchDangerScreen(url, score)
            }

        } catch (e: Exception) {
            Log.e(TAG, "API error: ${e.message}")
        } finally {
            connection?.disconnect()
        }
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
            if (intent != null) {
                startActivity(intent)
                Log.d(TAG, "Launched danger screen for: $url")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch danger screen: ${e.message}")
        }
    }

    private fun showDangerNotification(url: String, score: Double, message: String) {
        try {
            val openAppIntent = packageManager
                .getLaunchIntentForPackage(packageName)
                ?.apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    putExtra("danger_url", url)
                    putExtra("danger_score", score)
                    putExtra("show_danger", true)
                }
                ?.let {
                    PendingIntent.getActivity(
                        this, 0, it,
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                    )
                }

            val domain = try {
                android.net.Uri.parse(url).host ?: url
            } catch (e: Exception) { url }

            val notification = NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("⚠️ Dangerous Link Blocked!")
                .setContentText("$domain — $message")
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setDefaults(NotificationCompat.DEFAULT_ALL)
                .setVibrate(longArrayOf(0, 500, 200, 500))
                .setContentIntent(openAppIntent)
                .build()

            val manager = getSystemService(NotificationManager::class.java)
            manager.notify(System.currentTimeMillis().toInt(), notification)
            Log.d(TAG, "Notification sent for: $domain")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show notification: ${e.message}")
        }
    }

    override fun onInterrupt() {
        Log.d(TAG, "Accessibility service interrupted")
    }
}