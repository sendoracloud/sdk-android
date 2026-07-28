package com.sendoracloud.sdk.internal

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
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
 * Recursively convert an org.json tree into plain Kotlin collections.
 *
 * `org.json` hands back `JSONObject` / `JSONArray` for nested values, and
 * `JSONObject.NULL` (a singleton, NOT Kotlin null) for JSON nulls. Converting
 * only the top level leaves every nested value as a `JSONObject`, so an
 * ordinary `as? Map<String, Any?>` cast against it silently yields null —
 * which is exactly how the whole SDK reads a response envelope
 * (`response["data"] as? Map`, `data["user"] as? Map`, `data as? List`).
 * Converting the entire tree ONCE here, at the transport boundary, is what
 * makes those casts work; doing it per-call-site is how the shallow version
 * survived unnoticed.
 */
internal fun JSONObject.toDeepMap(): Map<String, Any?> =
    keys().asSequence().associateWith { key -> unwrapJson(opt(key)) }

internal fun JSONArray.toDeepList(): List<Any?> =
    (0 until length()).map { index -> unwrapJson(opt(index)) }

internal fun unwrapJson(value: Any?): Any? = when (value) {
    null, JSONObject.NULL -> null
    is JSONObject -> value.toDeepMap()
    is JSONArray -> value.toDeepList()
    else -> value
}

/** Parse a response body into plain Kotlin collections. Null when unparseable. */
internal fun parseJsonBody(raw: String): Map<String, Any?>? =
    runCatching { JSONObject(raw).toDeepMap() }.getOrNull()

/**
 * Stamp the HTTP status onto the envelope's `error` object so a caller can
 * classify a failure the backend gave no `code` for (a bare 5xx, a gateway
 * page). Deliberately does NOT synthesise an `error` when the body carries
 * none — its absence is what makes a caller fall back to its own default
 * code, and shipped apps string-match those.
 */
internal fun Map<String, Any?>.withErrorStatus(status: Int): Map<String, Any?> {
    @Suppress("UNCHECKED_CAST")
    val error = this["error"] as? Map<String, Any?> ?: return this
    return this + ("error" to (error + ("status" to status)))
}

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

    suspend fun post(path: String, body: Map<String, Any?>, extraHeaders: Map<String, String>? = null): Map<String, Any?>? {
        if (shouldSkip()) return null
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { request("POST", path, body, extraHeaders) }
        }
    }

    suspend fun get(path: String, extraHeaders: Map<String, String>? = null): Map<String, Any?>? {
        if (shouldSkip()) return null
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { request("GET", path, null, extraHeaders) }
        }
    }

    suspend fun delete(path: String, extraHeaders: Map<String, String>? = null): Map<String, Any?>? {
        if (shouldSkip()) return null
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { request("DELETE", path, null, extraHeaders) }
        }
    }

    /**
     * Rich response. Surfaces HTTP status + the typed `error.code` /
     * `error.message` envelope fields so callers (Links) can map backend
     * errors into typed exceptions instead of swallowing them as `null`.
     * Independent of the circuit breaker for HTTP 4xx — those are logical
     * errors from the caller's perspective, not transport failures.
     */
    data class RichResponse(
        val statusCode: Int,
        val body: Map<String, Any?>?,
        val errorCode: String?,
        val errorMessage: String?,
    )

    suspend fun requestWithDetails(
        method: String,
        path: String,
        body: Map<String, Any?>?,
        extraHeaders: Map<String, String>? = null,
    ): RichResponse {
        if (shouldSkip()) {
            return RichResponse(0, null, "NETWORK", "Circuit breaker open — too many recent failures")
        }
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { doRichRequest(method, path, body, extraHeaders) }
        } ?: RichResponse(0, null, "NETWORK", "Request timed out")
    }

    private fun doRichRequest(
        method: String,
        path: String,
        body: Map<String, Any?>?,
        extraHeaders: Map<String, String>? = null,
    ): RichResponse {
        val fullUrl = "$baseUrl/api/v1$path"
        if (!fullUrl.startsWith("https://") &&
            !fullUrl.startsWith("http://localhost") &&
            !fullUrl.startsWith("http://10.0.2.2") &&
            !fullUrl.startsWith("http://127.0.0.1")) {
            SendoraCloudLogger.error("ApiClient refusing non-HTTPS URL")
            return RichResponse(0, null, "NETWORK", "Non-HTTPS URL refused")
        }
        return try {
            val conn = URL(fullUrl).openConnection() as HttpURLConnection
            if (conn is HttpsURLConnection && pinnedSslContext != null) {
                conn.sslSocketFactory = pinnedSslContext.socketFactory
            }
            conn.requestMethod = method
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-API-Key", apiKey)
            // SDK-version telemetry (ADR-023 §2.1). Additive — backend ignores
            // today; enables per-version observability on auth/links/push calls
            // that carry no version signal in their body.
            conn.setRequestProperty("X-Sendora-SDK-Name", SDK_NAME)
            conn.setRequestProperty("X-Sendora-SDK-Version", SDK_VERSION)
            extraHeaders?.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            conn.connectTimeout = 5_000
            conn.readTimeout = 5_000
            if (body != null) {
                conn.doOutput = true
                val jsonBody = JSONObject(body).toString()
                OutputStreamWriter(conn.outputStream).use { it.write(jsonBody) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val raw = BufferedReader(InputStreamReader(stream)).use { it.readText() }
            val parsed = parseJsonBody(raw)
            if (code in 200..299) {
                recordSuccess()
                RichResponse(code, parsed, null, null)
            } else {
                // The breaker guards the TRANSPORT, so any answer from the
                // server clears it; only a 5xx or a thrown exception counts
                // as a failure. A 4xx is the backend disagreeing with the
                // request, and must never cost the caller its retry budget.
                if (code >= 500) recordFailure() else recordSuccess()
                @Suppress("UNCHECKED_CAST")
                val err = parsed?.get("error") as? Map<String, Any?>
                RichResponse(code, parsed, err?.get("code") as? String, err?.get("message") as? String)
            }
        } catch (e: Exception) {
            SendoraCloudLogger.debug("API error ($path): ${e.javaClass.simpleName}")
            recordFailure()
            RichResponse(0, null, "NETWORK", "Network error: ${e.javaClass.simpleName}")
        }
    }

    suspend fun postBatch(path: String, events: List<Map<String, Any?>>): Boolean {
        val response = post(path, mapOf("events" to events))
        return (response?.get("success") as? Boolean) == true
    }

    private fun request(
        method: String,
        path: String,
        body: Map<String, Any?>?,
        extraHeaders: Map<String, String>?,
    ): Map<String, Any?>? {
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
            conn.requestMethod = method
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-API-Key", apiKey)
            // SDK-version telemetry (ADR-023 §2.1). Additive — backend ignores today.
            conn.setRequestProperty("X-Sendora-SDK-Name", SDK_NAME)
            conn.setRequestProperty("X-Sendora-SDK-Version", SDK_VERSION)
            extraHeaders?.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            conn.connectTimeout = 5_000
            conn.readTimeout = 5_000
            if (body != null) {
                conn.doOutput = true
                val jsonBody = JSONObject(body).toString()
                OutputStreamWriter(conn.outputStream).use { it.write(jsonBody) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val response = BufferedReader(InputStreamReader(stream)).use { it.readText() }
            if (code in 200..299) {
                recordSuccess()
                parseJsonBody(response)
            } else {
                // A 4xx is the backend answering, not the transport failing:
                // returning null here threw away `error.code` /
                // `error.details.retryAfterSeconds` and left every caller
                // unable to tell a wrong password from being offline. It also
                // let a wrong password arm the circuit breaker and lock the
                // client out of its own retry.
                if (code >= 500) recordFailure() else recordSuccess()
                parseJsonBody(response)?.withErrorStatus(code)
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

    /**
     * Circuit breaker gate. Purely time-based (half-open by construction):
     * each failure pushes `nextAllowedAfter` forward with exponential backoff
     * (capped at `maxBackoffMs`), and once that window elapses ONE probe
     * request is allowed through. A probe success calls `recordSuccess()` and
     * resets the breaker; a probe failure re-arms the backoff. We deliberately
     * do NOT hard-trip on `consecutiveFailures` alone — a count-only block can
     * never reset (no request is attempted → no success → no reset), which
     * wedged the client for the whole process lifetime after a transient blip.
     */
    private fun shouldSkip(): Boolean {
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
