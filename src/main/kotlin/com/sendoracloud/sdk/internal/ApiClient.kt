package com.sendoracloud.sdk.internal

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * HTTPS-only client with exponential backoff + circuit breaker.
 * Optionally enforces SPKI certificate pinning when `pinnedSPKIHashes`
 * is non-empty — useful against user-installed enterprise / MitM CAs
 * targeting auth tokens. Never throws — errors log and the call
 * returns null.
 */
internal class ApiClient(
    baseUrl: String,
    private val apiKey: String,
    pinnedSPKIHashes: List<String> = emptyList(),
) {
    private val baseUrl: String = baseUrl.trimEnd('/')
    private val consecutiveFailures = AtomicInteger(0)
    private val nextAllowedAfter = AtomicLong(0)

    private val maxFailures = 10
    private val maxBackoffMs = 60_000L

    /**
     * Pinned SSL context. Null when no pins configured → plain
     * HttpsURLConnection trust evaluation kicks in.
     */
    private val pinnedSslContext: SSLContext? = if (pinnedSPKIHashes.isEmpty()) {
        null
    } else {
        runCatching {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as java.security.KeyStore?)
            val systemTm = tmf.trustManagers
                .filterIsInstance<X509TrustManager>()
                .first()
            val pinningTm = SpkiPinningTrustManager(systemTm, pinnedSPKIHashes.toSet())
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf<TrustManager>(pinningTm), null)
            ctx
        }.onFailure { SendoraCloudLogger.error("Failed to init pinned SSL context", it) }
            .getOrNull()
    }

    suspend fun post(path: String, body: Map<String, Any?>): Map<String, Any?>? {
        if (shouldSkip()) return null
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { postInternal(path, body) }
        }
    }

    suspend fun postBatch(path: String, events: List<Map<String, Any?>>): Boolean {
        val response = post(path, mapOf("events" to events))
        return (response?.get("success") as? Boolean) == true
    }

    private fun postInternal(path: String, body: Map<String, Any?>): Map<String, Any?>? {
        val fullUrl = "$baseUrl/api/v1$path"
        if (!fullUrl.startsWith("https://") &&
            !fullUrl.startsWith("http://localhost") &&
            !fullUrl.startsWith("http://10.0.2.2") &&
            !fullUrl.startsWith("http://127.0.0.1")) {
            SendoraCloudLogger.error("ApiClient refusing non-HTTPS URL")
            return null
        }
        return try {
            val conn = URL(fullUrl).openConnection() as HttpURLConnection
            // Apply pinning to https connections only.
            if (conn is HttpsURLConnection && pinnedSslContext != null) {
                conn.sslSocketFactory = pinnedSslContext.socketFactory
            }
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-API-Key", apiKey)
            conn.connectTimeout = 5_000
            conn.readTimeout = 5_000
            conn.doOutput = true
            val jsonBody = JSONObject(body).toString()
            OutputStreamWriter(conn.outputStream).use { it.write(jsonBody) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val response = BufferedReader(InputStreamReader(stream)).use { it.readText() }
            if (code !in 200..299) {
                recordFailure()
                null
            } else {
                recordSuccess()
                val json = JSONObject(response)
                json.keys().asSequence().associateWith { key -> json.get(key) }
            }
        } catch (e: Exception) {
            // No response-body details from this layer — keeps backend
            // error codes (which may leak account state on auth paths)
            // out of Logcat where other apps with READ_LOGS could read.
            SendoraCloudLogger.debug("API error ($path): ${e.javaClass.simpleName}")
            recordFailure()
            null
        }
    }

    private fun shouldSkip(): Boolean {
        if (consecutiveFailures.get() > maxFailures) return true
        return System.currentTimeMillis() < nextAllowedAfter.get()
    }

    private fun recordSuccess() {
        consecutiveFailures.set(0)
        nextAllowedAfter.set(0)
    }

    private fun recordFailure() {
        val n = consecutiveFailures.incrementAndGet()
        val delay = minOf(maxBackoffMs, (1L shl n.coerceAtMost(20)) * 1000L)
        nextAllowedAfter.set(System.currentTimeMillis() + delay)
    }
}

/**
 * X509TrustManager that delegates default trust evaluation to the
 * system trust manager AND additionally requires the leaf's SPKI
 * SHA-256 (or one in its chain) to match one of the configured pins.
 * Walks the chain so a backup pin on an intermediate also satisfies
 * (rotation safety net).
 */
private class SpkiPinningTrustManager(
    private val delegate: X509TrustManager,
    private val pins: Set<String>,
) : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        delegate.checkClientTrusted(chain, authType)
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        delegate.checkServerTrusted(chain, authType)
        if (chain.isNullOrEmpty()) {
            throw CertificateException("Empty cert chain")
        }
        for (cert in chain) {
            val hash = spkiSha256Base64(cert)
            if (pins.contains(hash)) return
        }
        throw CertificateException("Certificate pin mismatch — no certificate in chain matches configured pins")
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

    private fun spkiSha256Base64(cert: X509Certificate): String {
        val spki = cert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256").digest(spki)
        return android.util.Base64.encodeToString(digest, android.util.Base64.NO_WRAP)
    }
}
