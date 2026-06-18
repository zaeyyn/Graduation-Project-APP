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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

class LinkGuardVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    @Volatile
    private var isRunning = false

    companion object {
        // Fired for EVERY checked domain (SAFE or DANGER) so the Flutter side
        // can keep its history/stats accurate. Previously this only fired for
        // DANGER under a different name, which is why MainActivity's receiver
        // never matched it.
        const val ACTION_LINK_CHECKED = "com.example.flutter_application_1.LINK_CHECKED"
        private const val TAG = "LinkGuard"
        private const val API_URL = "https://linkguard-api-yy7v.onrender.com/check"
        private const val TIMEOUT_MS = 15_000
        private const val CHANNEL_ID = "linkguard_channel"
        private const val NOTIFICATION_ID = 1
        private const val DNS_SERVER = "8.8.8.8"
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

    /**
     * Sets up the VPN so ONLY traffic to the DNS server passes through our tun
     * interface. Every other connection (the real page load once a domain is
     * resolved) bypasses the VPN entirely and behaves like a normal network
     * request. This is what fixes "safe" links timing out — previously ALL
     * traffic (0.0.0.0/0) was routed into the tun but never actually forwarded
     * anywhere, so nothing other than DNS classification ever worked.
     */
    private fun startVpn() {
        vpnInterface = Builder()
            .addAddress("10.0.0.2", 24)
            .addDnsServer(DNS_SERVER)
            .addRoute(DNS_SERVER, 32)
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

                    val domain = parseDnsQuery(buffer, length)
                    if (domain != null && domain.isNotEmpty() && !domain.startsWith(".")) {
                        Log.d(TAG, "DNS query: $domain")
                        checkDomain(domain)
                    }

                    // Actually resolve the query and hand the real answer back
                    // to the device. This replaces the old line that echoed
                    // the outgoing packet straight back into the same
                    // interface, which never reached the real internet.
                    handleDnsPacket(buffer.copyOf(length), outputStream)
                }
            } catch (e: Exception) {
                Log.e(TAG, "VPN thread error: ${e.message}")
            }
        }.start()
    }

    /**
     * Forwards a captured DNS query to the real DNS server using a protected
     * socket (so the request itself doesn't loop back into the VPN), then
     * writes the real response back into the tun interface so the requesting
     * app gets a proper, real answer instead of hanging forever.
     */
    private fun handleDnsPacket(packet: ByteArray, outputStream: FileOutputStream) {
        try {
            val length = packet.size
            if (length < 28) return // smaller than IP(20) + UDP(8) header

            val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
            val udpOffset = ipHeaderLen
            if (udpOffset + 8 > length) return

            val srcPort = ((packet[udpOffset].toInt() and 0xFF) shl 8) or
                    (packet[udpOffset + 1].toInt() and 0xFF)

            val dnsOffset = udpOffset + 8
            if (dnsOffset >= length) return
            val dnsPayload = packet.copyOfRange(dnsOffset, length)

            val socket = DatagramSocket()
            try {
                protect(socket) // critical: keeps this socket outside the VPN tunnel
                socket.soTimeout = 5000
                val dnsServerAddr = InetAddress.getByName(DNS_SERVER)
                socket.send(DatagramPacket(dnsPayload, dnsPayload.size, dnsServerAddr, 53))

                val responseBuffer = ByteArray(1024)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(responsePacket)

                val reply = buildDnsReplyPacket(
                    originalPacket = packet,
                    ipHeaderLen = ipHeaderLen,
                    srcPort = srcPort,
                    dnsResponse = responsePacket.data.copyOfRange(0, responsePacket.length)
                )
                outputStream.write(reply)
            } finally {
                socket.close()
            }
        } catch (e: Exception) {
            Log.e(TAG, "DNS forward error: ${e.message}")
        }
    }

    /**
     * Builds a real IPv4/UDP packet wrapping the DNS response, with source and
     * destination addresses/ports swapped relative to the original query, so
     * the device's network stack treats it as a genuine incoming reply.
     */
    private fun buildDnsReplyPacket(
        originalPacket: ByteArray,
        ipHeaderLen: Int,
        srcPort: Int,
        dnsResponse: ByteArray
    ): ByteArray {
        val udpLen = 8 + dnsResponse.size
        val totalLen = ipHeaderLen + udpLen
        val reply = ByteArray(totalLen)

        // Copy the IP header, then swap source/destination addresses
        System.arraycopy(originalPacket, 0, reply, 0, ipHeaderLen)
        for (i in 0 until 4) {
            reply[12 + i] = originalPacket[16 + i] // new src IP = old dest IP
            reply[16 + i] = originalPacket[12 + i] // new dest IP = old src IP
        }

        // Update total length field (bytes 2-3 of the IP header)
        reply[2] = ((totalLen shr 8) and 0xFF).toByte()
        reply[3] = (totalLen and 0xFF).toByte()

        // Clear checksum before recomputing (bytes 10-11)
        reply[10] = 0
        reply[11] = 0

        // UDP header: src port becomes 53, dest port becomes the original source port
        val udpStart = ipHeaderLen
        reply[udpStart] = 0
        reply[udpStart + 1] = 53
        reply[udpStart + 2] = ((srcPort shr 8) and 0xFF).toByte()
        reply[udpStart + 3] = (srcPort and 0xFF).toByte()
        reply[udpStart + 4] = ((udpLen shr 8) and 0xFF).toByte()
        reply[udpStart + 5] = (udpLen and 0xFF).toByte()
        reply[udpStart + 6] = 0 // UDP checksum is optional for IPv4 — left unset
        reply[udpStart + 7] = 0

        System.arraycopy(dnsResponse, 0, reply, udpStart + 8, dnsResponse.size)

        val checksum = computeIpChecksum(reply, ipHeaderLen)
        reply[10] = ((checksum shr 8) and 0xFF).toByte()
        reply[11] = (checksum and 0xFF).toByte()

        return reply
    }

    private fun computeIpChecksum(packet: ByteArray, headerLen: Int): Int {
        var sum = 0
        var i = 0
        while (i < headerLen) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    /**
     * Parse a DNS query packet to extract the queried domain name.
     * DNS packet structure over UDP/IP:
     * - IP header: 20 bytes (IPv4)
     * - UDP header: 8 bytes
     * - DNS header: 12 bytes
     * - DNS question: variable (domain name + type + class)
     */
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
            val isQuery = (flags and 0x8000) == 0
            if (!isQuery) return null

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

    private val checkedDomains = mutableMapOf<String, Long>()
    private val CACHE_TTL_MS = 60_000L // 1 minute cache

    private fun checkDomain(domain: String) {
        // Skip system/internal domains
        if (domain.endsWith(".local") ||
            domain.endsWith(".internal") ||
            domain.endsWith(".arpa") ||
            (domain.contains("google") && (domain.endsWith(".com") || domain.endsWith(".net"))) ||
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

                // Always report the result back to Flutter (SAFE and DANGER)
                // so the home screen stats/history stay in sync with what the
                // VPN actually detected in the background.
                val checkedIntent = Intent(ACTION_LINK_CHECKED).apply {
                    putExtra("url", fullUrl)
                    putExtra("verdict", verdict)
                    putExtra("score", score)
                    setPackage(packageName)
                }
                sendBroadcast(checkedIntent)

                if (verdict == "DANGER") {
                    Log.d(TAG, "DANGER detected: $domain")
                    showThreatNotification(domain)
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
