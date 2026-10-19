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
 * The status-carrying request seam (Links). `ApiClient` implements it; the JVM
 * suite substitutes a scripted double.
 */
internal interface RichTransport {
    suspend fun requestWithDetails(
        method: String,
        path: String,
        body: Map<String, Any?>?,
        extraHeaders: Map<String, String>? = null,
    ): ApiClient.RichResponse
}

/**
 * Stamp a server-supplied wait onto a refusal's `error.details.retryAfterSeconds`
 * when the body did not already carry one (the backend sends both since s58.402;
 * this keeps a header-only answer — a proxy, an older deploy — readable by the
 * callers that only look at the envelope).
 */
internal fun Map<String, Any?>.withRetryAfter(seconds: Long?): Map<String, Any?> {
    if (seconds == null) return this
    @Suppress("UNCHECKED_CAST")
    val error = this["error"] as? Map<String, Any?> ?: return this
    @Suppress("UNCHECKED_CAST")
    val details = error["details"] as? Map<String, Any?> ?: emptyMap()
    if (details["retryAfterSeconds"] is Number) return this
    return this + ("error" to (error + ("details" to (details + ("retryAfterSeconds" to seconds)))))
}

/**
 * HTTPS-only client with a full-jitter circuit breaker.
 * Optionally enforces SPKI certificate pinning when `pinnedSPKIHashes`
 * is non-empty — useful against user-installed enterprise / MitM CAs
 * targeting auth tokens. Never throws — errors log and the call
 * returns null.
 *
 * 4.28.0 (F67): reads `Retry-After` and `cf-mitigated` off every answer.
 *  - A 503 or an edge challenge (`cf-mitigated`) counts as a transport failure and
 *    the breaker waits AT LEAST the server's `Retry-After` (an edge challenge at
 *    least 60 s). The jitter is FULL — random(0, min(60 s, 2^n s)) — never the
 *    fixed doubling that lined every device up on the same second.
 *  - A 429 is the caller's own budget: it holds the breaker for the server's wait,
 *    clamped to 60 s here, because a 429 can be a per-route budget (support's
 *    per-ticket reply limit is 600 s) and a whole-client hold that long would
 *    black out events and the token refresh over one ticket. The full wait is
 *    surfaced to the caller (envelope `error.details.retryAfterSeconds`,
 *    [RichResponse.retryAfterSeconds]), which is where a route-scoped retry
 *    belongs — the event queue honours it up to an hour.
 *  - Any other 4xx is the backend answering, never a transport failure: it never
 *    trips the breaker.
 *  - An edge challenge is NOT the backend answering. On the envelope path it is
 *    `null` (exactly "the server never saw it" — so an auth call can never read a
 *    challenge as a dead credential and never wipe a session over one); on the
 *    rich path it is [RichResponse.cfMitigated] with code `CF_CHALLENGE`.
 */
internal class ApiClient(
    baseUrl: String,
    private val apiKey: String,
    pinnedSPKIHashes: List<String> = emptyList(),
    private val clock: () -> Long = System::currentTimeMillis,
    private val random: (Long) -> Long = Backoff.defaultRandom,
) : AuthTransport, RichTransport {
    private val baseUrl: String = baseUrl.trimEnd('/')
    private val consecutiveFailures = AtomicInteger(0)
    private val nextAllowedAfter = AtomicLong(0)

    /** The longest a 429 holds the WHOLE client (see the class note). */
    private val maxRateLimitHoldMs = 60_000L

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

    override suspend fun post(path: String, body: Map<String, Any?>, extraHeaders: Map<String, String>?): Map<String, Any?>? {
        if (shouldSkip()) return null
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { request("POST", path, body, extraHeaders) }
        }
    }

    override suspend fun get(path: String, extraHeaders: Map<String, String>?): Map<String, Any?>? {
        if (shouldSkip()) return null
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { request("GET", path, null, extraHeaders) }
        }
    }

    override suspend fun delete(path: String, extraHeaders: Map<String, String>?): Map<String, Any?>? {
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
     *
     * 4.28.0: [retryAfterSeconds] is the server's `Retry-After` (or, when the
     * breaker refused the call locally, the time left on it); [cfMitigated] is
     * true when Cloudflare challenged the request — the status is then the
     * edge's (403 / 503), never the backend's verdict.
     */
    data class RichResponse(
        val statusCode: Int,
        val body: Map<String, Any?>?,
        val errorCode: String?,
        val errorMessage: String?,
        val retryAfterSeconds: Long? = null,
        val cfMitigated: Boolean = false,
    )

    override suspend fun requestWithDetails(
        method: String,
        path: String,
        body: Map<String, Any?>?,
        extraHeaders: Map<String, String>?,
    ): RichResponse {
        if (shouldSkip()) {
            val leftMs = (nextAllowedAfter.get() - clock()).coerceAtLeast(0L)
            return RichResponse(0, null, "NETWORK", "Circuit breaker open — too many recent failures", retryAfterSeconds = (leftMs + 999L) / 1000L)
        }
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { doRichRequest(method, path, body, extraHeaders) }
        } ?: RichResponse(0, null, "NETWORK", "Request timed out")
    }

    /** One HTTP exchange's raw outcome; `status == 0` means no answer (refused URL / I/O failure). */
    private class Exchange(val status: Int, val raw: String?, val retryAfterSeconds: Long?, val cfMitigated: Boolean)

    private fun isAllowedUrl(fullUrl: String): Boolean =
        fullUrl.startsWith("https://") ||
            fullUrl.startsWith("http://localhost") ||
            fullUrl.startsWith("http://10.0.2.2") ||
            fullUrl.startsWith("http://127.0.0.1")

    /**
     * The single wire exchange both response shapes are built from. Records the
     * breaker outcome; never throws.
     */
    private fun exchange(
        method: String,
        path: String,
        body: Map<String, Any?>?,
        extraHeaders: Map<String, String>?,
    ): Exchange {
        val fullUrl = "$baseUrl/api/v1$path"
        if (!isAllowedUrl(fullUrl)) {
            SendoraCloudLogger.error("ApiClient refusing non-HTTPS URL")
            return Exchange(0, null, null, false)
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
            val retryAfter = Backoff.parseRetryAfter(conn.getHeaderField("Retry-After"), clock())
            val cf = Backoff.isCfMitigated(conn.getHeaderField("cf-mitigated"))
            // ⚠ A bodiless refusal has a null errorStream; reading it used to throw
            // and turn a 4xx into a "network failure" that armed the breaker.
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val raw = stream?.let { s -> BufferedReader(InputStreamReader(s)).use { it.readText() } }
            recordAnswer(code, retryAfter, cf)
            Exchange(code, raw, retryAfter, cf)
        } catch (e: Exception) {
            // No response-body details from this layer — keeps backend
            // error codes (which may leak account state on auth paths)
            // out of Logcat where other apps with READ_LOGS could read.
            SendoraCloudLogger.debug("API error ($path): ${e.javaClass.simpleName}")
            recordFailure(null, false)
            Exchange(0, null, null, false)
        }
    }

    private fun doRichRequest(
        method: String,
        path: String,
        body: Map<String, Any?>?,
        extraHeaders: Map<String, String>? = null,
    ): RichResponse {
        val x = exchange(method, path, body, extraHeaders)
        if (x.status == 0) return RichResponse(0, null, "NETWORK", "Network error")
        if (x.cfMitigated) {
            return RichResponse(x.status, null, "CF_CHALLENGE", "The edge challenged this request — retry later", x.retryAfterSeconds, true)
        }
        val parsed = x.raw?.let { parseJsonBody(it) }
        if (x.status in 200..299) return RichResponse(x.status, parsed, null, null, x.retryAfterSeconds)
        @Suppress("UNCHECKED_CAST")
        val err = parsed?.get("error") as? Map<String, Any?>
        return RichResponse(x.status, parsed, err?.get("code") as? String, err?.get("message") as? String, x.retryAfterSeconds)
    }

    /**
     * The event-batch send (ADR-023 §7 ack-before-remove). Status + the retry
     * signals reach the queue so it can tell "drop this chunk" (a permanent 4xx)
     * from "keep it and wait at least this long".
     */
    suspend fun sendEvents(path: String, body: Map<String, Any?>): RichResponse = requestWithDetails("POST", path, body)

    private fun request(
        method: String,
        path: String,
        body: Map<String, Any?>?,
        extraHeaders: Map<String, String>?,
    ): Map<String, Any?>? {
        val x = exchange(method, path, body, extraHeaders)
        if (x.status == 0) return null
        // ⚠ An edge challenge is not the backend's answer. Returning it as a
        // refusal would let a 403 challenge classify as INVALID_CREDENTIAL on an
        // auth call; null is "offline" — retryable, never a dead credential.
        if (x.cfMitigated) return null
        val parsed = x.raw?.let { parseJsonBody(it) }
        if (x.status in 200..299) return parsed
        // A 4xx is the backend answering, not the transport failing:
        // returning null here threw away `error.code` /
        // `error.details.retryAfterSeconds` and left every caller
        // unable to tell a wrong password from being offline.
        return parsed?.withErrorStatus(x.status)?.withRetryAfter(x.retryAfterSeconds)
    }

    /**
     * Circuit breaker gate. Purely time-based (half-open by construction):
     * each failure pushes `nextAllowedAfter` forward (full jitter, at least the
     * server's wait), and once that window elapses ONE probe request is allowed
     * through. A probe success calls `recordSuccess()` and resets the breaker; a
     * probe failure re-arms it. We deliberately do NOT hard-trip on
     * `consecutiveFailures` alone — a count-only block can never reset (no
     * request is attempted → no success → no reset), which wedged the client
     * for the whole process lifetime after a transient blip.
     */
    private fun shouldSkip(): Boolean {
        return clock() < nextAllowedAfter.get()
    }

    /** Classify one answer for the breaker. Internal for the JVM suite. */
    internal fun recordAnswer(status: Int, retryAfterSeconds: Long?, cfMitigated: Boolean) {
        when {
            cfMitigated -> recordFailure(retryAfterSeconds, true)
            status in 200..299 -> recordSuccess()
            status == 429 -> holdFor(minOf(Backoff.serverFloorMs(retryAfterSeconds, false), maxRateLimitHoldMs))
            status >= 500 -> recordFailure(if (status == 503) retryAfterSeconds else null, false)
            // ⚠ A plain 4xx never trips the breaker — and must not cost the
            // caller its retry budget (a wrong password is not an outage).
            else -> recordSuccess()
        }
    }

    /** Milliseconds until the breaker lets a request through (0 = closed). Internal for the JVM suite. */
    internal fun breakerWaitMs(): Long = (nextAllowedAfter.get() - clock()).coerceAtLeast(0L)

    private fun recordSuccess() {
        consecutiveFailures.set(0)
        nextAllowedAfter.set(0)
    }

    /** A 429's hold: not a failure (the count is untouched), only a floor on the next attempt. */
    private fun holdFor(ms: Long) {
        if (ms <= 0L) return
        val until = clock() + ms
        nextAllowedAfter.updateAndGet { maxOf(it, until) }
    }

    private fun recordFailure(retryAfterSeconds: Long?, cfMitigated: Boolean) {
        val n = consecutiveFailures.incrementAndGet()
        val delay = Backoff.delayMs(n, retryAfterSeconds, cfMitigated, random)
        nextAllowedAfter.set(clock() + delay)
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
