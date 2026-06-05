package com.example.flutter_application_1

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

class LinkGuardAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "LinkGuardAccessibility"
        const val ACTION_URL_DETECTED = "com.example.flutter_application_1.URL_DETECTED"
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        val info = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_VIEW_CLICKED or
                    AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or
                    AccessibilityEvent.TYPE_VIEW_FOCUSED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                    AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            notificationTimeout = 100
        }
        serviceInfo = info
        Log.d(TAG, "Accessibility service connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        try {
            val source = event.source ?: return
            extractUrls(source)
        } catch (e: Exception) {
            Log.e(TAG, "Error processing accessibility event: ${e.message}")
        }
    }

    private fun extractUrls(node: AccessibilityNodeInfo) {
        try {
            val text = node.text?.toString() ?: ""
            val contentDesc = node.contentDescription?.toString() ?: ""
            listOf(text, contentDesc).forEach { str ->
                val url = extractUrl(str)
                if (url != null) {
                    Log.d(TAG, "URL detected: $url")
                    sendUrlDetected(url)
                }
            }
            for (i in 0 until node.childCount) {
                val child = node.getChild(i) ?: continue
                extractUrls(child)
                child.recycle()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting URLs: ${e.message}")
        }
    }

    private fun extractUrl(text: String): String? {
        if (text.isBlank()) return null
        val urlRegex = Regex("""https?://[^\s<>"{}|\\^`\[\]]+""")
        return urlRegex.find(text)?.value
    }

    private fun sendUrlDetected(url: String) {
        val intent = Intent(ACTION_URL_DETECTED).apply {
            putExtra("url", url)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    override fun onInterrupt() {
        Log.d(TAG, "Accessibility service interrupted")
    }
}