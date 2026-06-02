package com.sendoracloud.sdk

import android.content.res.Resources
import android.net.Uri
import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.SendoraCloudLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Deep-link surface for the Android SDK (s58.50 rewrite — Branch / Firebase parity).
 *
 * Surface:
 *   • [create] / [prewarm]                  — mint + background-mint-with-cache.
 *   • [handleAppLink]                       — warm-path resolve.
 *   • [matchDeferred]                       — cold-launch deferred match
 *                                              (auto-probes Play Install Referrer
 *                                              + canonical fingerprint).
 *   • [onLinkOpened]                        — observer (warm + deferred).
 *   • [revoke]                              — soft-delete.
 *   • [getStats]                            — totals + breakdowns.
 *   • [computeDeviceFingerprint] (static)   — canonical recipe matching iOS / RN.
 *   • [LinkError]                           — typed errors with codes.
 */
class SendoraCloudLinks internal constructor(
    private val client: ApiClient,
    private val packageName: String?,
    private val linkHosts: List<String>,
    private val scope: CoroutineScope,
) {

    // ---- typed errors ------------------------------------------------

    enum class LinkErrorCode {
        BUNDLE_MISMATCH,
        DATA_TOO_LARGE,
        EXPIRED,
        NETWORK,
        RATE_LIMITED,
        NOT_FOUND,
        UNAUTHORIZED,
        INVALID_INPUT,
        PLAN_LIMIT,
        FALLBACK_REQUIRED,
        SERVER,
        UNKNOWN,
    }

    class LinkError(
        val code: LinkErrorCode,
        message: String,
        val statusCode: Int = 0,
    ) : RuntimeException(message)

    // ---- types -------------------------------------------------------

    data class LinkCreateInput(
        val title: String,
        /** **Optional as of 3.8.0** — backend defaults from your project's apps registry. */
        val fallbackUrl: String? = null,
        val iosDeepLinkPath: String? = null,
        val androidDeepLinkPath: String? = null,
        val linkData: Map<String, Any>? = null,
        val ogTitle: String? = null,
        val ogDescription: String? = null,
        val ogImageUrl: String? = null,
        val campaign: String? = null,
        val source: String? = null,
        val medium: String? = null,
        val channel: String? = null,
        val tags: List<String>? = null,
        val expiresAt: String? = null,
        val iosBundleId: String? = null,
        val androidPackageName: String? = null,
    )

    data class LinkCreateResult(
        val id: String,
        val shortcode: String,
        val url: String,
        val iosDeepLinkPath: String?,
        val androidDeepLinkPath: String?,
        val fallbackUrl: String,
        val linkData: Map<String, Any>,
    )

    data class LinkOpenedEvent(
        val shortcode: String,
        val linkData: Map<String, Any>,
        val iosDeepLinkPath: String?,
        val androidDeepLinkPath: String?,
        val isDeferred: Boolean,
    )

    data class DeferredMatchInput(
        val installReferrer: String? = null,
        val fingerprintHash: String? = null,
    )

    data class LinkStats(
        val totalClicks: Int,
        val uniqueClicks: Int,
        val deferredMatches: Int,
        val byDevice: List<Pair<String?, Int>>,
        val byCountry: List<Pair<String?, Int>>,
        val byOs: List<Pair<String?, Int>>,
    )

    // ---- observers ---------------------------------------------------

    private data class HandlerEntry(val token: UUID, val handler: (LinkOpenedEvent) -> Unit)

    private val handlers = CopyOnWriteArrayList<HandlerEntry>()

    fun onLinkOpened(handler: (LinkOpenedEvent) -> Unit): UUID {
        val token = UUID.randomUUID()
        handlers.add(HandlerEntry(token, handler))
        return token
    }

    fun removeLinkOpenedHandler(token: UUID) {
        handlers.removeAll { it.token == token }
    }

    private suspend fun emit(event: LinkOpenedEvent) {
        withContext(Dispatchers.Main) {
            handlers.forEach {
                try { it.handler(event) }
                catch (e: Throwable) {
                    SendoraCloudLogger.error("onLinkOpened handler threw: ${e.message}", e)
                }
            }
        }
    }

    // ---- prewarm cache -----------------------------------------------

    private data class PrewarmEntry(
        val result: Result<LinkCreateResult>? = null,
        val waiters: MutableList<(Result<LinkCreateResult>) -> Unit> = mutableListOf(),
        val createdAtMs: Long = System.currentTimeMillis(),
    )

    private val prewarmCache = mutableMapOf<String, PrewarmEntry>()
    private val cacheMutex = Mutex()
    private val prewarmTtlMs = 5 * 60 * 1000L
    private val prewarmMax = 50

    /**
     * Wave 28 — concurrent-mint cap. A runaway loop calling `prewarm()`
     * (eg in a Compose LazyColumn item composable) would otherwise burn
     * through the backend's per-key rate limit + customer's plan quota.
     * 5 inflight matches real share-row UIs.
     */
    private var prewarmInflight = 0
    private val prewarmMaxInflight = 5

    private fun cacheKey(input: LinkCreateInput, override: String?): String {
        if (override != null) return "k:$override"
        val body = buildCreateBody(input)
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(canonicalJson(body).toByteArray(Charsets.UTF_8))
        return "s:" + digest.take(12).joinToString("") { "%02x".format(it) }
    }

    private fun canonicalJson(body: Map<String, Any?>): String {
        // Sort keys for stable hash. Values JSON-stringified shallowly —
        // good enough for our cache-key purposes (no need to canonicalise
        // nested objects, two prewarm calls with the same shape produce
        // the same Map iteration order anyway when callers reuse data).
        val sorted = body.toSortedMap()
        return sorted.entries.joinToString(",", "{", "}") { (k, v) -> "\"$k\":${v.toString()}" }
    }

    private suspend fun evictExpired() {
        cacheMutex.withLock {
            val now = System.currentTimeMillis()
            val stale = prewarmCache.filterValues { now - it.createdAtMs > prewarmTtlMs }.keys.toList()
            for (k in stale) prewarmCache.remove(k)
            while (prewarmCache.size > prewarmMax) {
                val oldest = prewarmCache.minByOrNull { it.value.createdAtMs }?.key ?: break
                prewarmCache.remove(oldest)
            }
        }
    }

    private fun buildCreateBody(input: LinkCreateInput): Map<String, Any?> = buildMap {
        put("title", input.title)
        input.fallbackUrl?.let { put("fallbackUrl", it) }
        input.iosDeepLinkPath?.let { put("iosDeepLinkPath", it) }
        input.androidDeepLinkPath?.let { put("androidDeepLinkPath", it) }
        input.linkData?.let { put("linkData", it) }
        input.ogTitle?.let { put("ogTitle", it) }
        input.ogDescription?.let { put("ogDescription", it) }
        input.ogImageUrl?.let { put("ogImageUrl", it) }
        input.campaign?.let { put("campaign", it) }
        input.source?.let { put("source", it) }
        input.medium?.let { put("medium", it) }
        input.channel?.let { put("channel", it) }
        input.tags?.let { put("tags", it) }
        input.expiresAt?.let { put("expiresAt", it) }
        input.iosBundleId?.let { put("iosBundleId", it) }
        (input.androidPackageName ?: packageName)?.let { put("androidPackageName", it) }
    }

    /**
     * Background-mint + cache. Fire-and-forget.
     *
     * Wave 28 — silently drops the call when more than
     * [prewarmMaxInflight] mints are already in flight. Prewarm is
     * fire-and-forget by contract; an overflow `prewarm()` is fine to
     * skip because the next matching `create()` will do the mint
     * inline. Caps unbounded fan-out from runaway loops.
     */
    fun prewarm(input: LinkCreateInput, key: String? = null) {
        if (input.title.isEmpty()) return
        scope.launch {
            val ck = cacheKey(input, key)
            evictExpired()
            val shouldRun = cacheMutex.withLock {
                if (prewarmCache.containsKey(ck)) return@withLock false
                if (prewarmInflight >= prewarmMaxInflight) return@withLock false
                prewarmInflight++
                prewarmCache[ck] = PrewarmEntry()
                true
            }
            if (!shouldRun) return@launch
            val result = doCreate(input)
            val waiters = cacheMutex.withLock {
                prewarmInflight--
                val e = prewarmCache[ck]
                if (e != null) {
                    if (result.isFailure) {
                        prewarmCache.remove(ck)
                    } else {
                        prewarmCache[ck] = e.copy(result = result, createdAtMs = System.currentTimeMillis())
                    }
                    e.waiters.toList()
                } else emptyList()
            }
            waiters.forEach { it(result) }
        }
    }

    /** Mint a link. Uses prewarm cache when input matches. */
    fun create(
        input: LinkCreateInput,
        prewarmKey: String? = null,
        onResult: (Result<LinkCreateResult>) -> Unit,
    ) {
        if (input.title.isEmpty()) {
            onResult(Result.failure(LinkError(LinkErrorCode.INVALID_INPUT, "title is required")))
            return
        }
        scope.launch {
            val ck = cacheKey(input, prewarmKey)
            evictExpired()
            val cached: Pair<PrewarmEntry?, Boolean> = cacheMutex.withLock {
                val e = prewarmCache[ck]
                if (e?.result != null) {
                    prewarmCache.remove(ck) // single-use
                    Pair(e, false)
                } else if (e != null) {
                    e.waiters.add { withContext(Dispatchers.Main) { onResult(it) } }
                    Pair(e, true)
                } else Pair(null, false)
            }
            if (cached.first?.result != null) {
                withContext(Dispatchers.Main) { onResult(cached.first!!.result!!) }
                return@launch
            }
            if (cached.second) return@launch // waiter attached
            val result = doCreate(input)
            withContext(Dispatchers.Main) { onResult(result) }
        }
    }

    private suspend fun doCreate(input: LinkCreateInput): Result<LinkCreateResult> {
        val rich = client.requestWithDetails("POST", "/sdk/links", buildCreateBody(input))
        if (rich.statusCode !in 200..299) {
            return Result.failure(mapError(rich.statusCode, rich.errorCode, rich.errorMessage))
        }
        @Suppress("UNCHECKED_CAST")
        val data = rich.body?.get("data") as? Map<String, Any?>
        val id = data?.get("id") as? String
        val shortcode = data?.get("shortcode") as? String
        val url = data?.get("url") as? String
        val fallback = data?.get("fallbackUrl") as? String
        if (id == null || shortcode == null || url == null || fallback == null) {
            return Result.failure(LinkError(LinkErrorCode.SERVER, "links.create returned an unexpected payload", rich.statusCode))
        }
        @Suppress("UNCHECKED_CAST")
        val linkData = (data["linkData"] as? Map<String, Any>) ?: emptyMap()
        return Result.success(LinkCreateResult(
            id = id,
            shortcode = shortcode,
            url = url,
            iosDeepLinkPath = data["iosDeepLinkPath"] as? String,
            androidDeepLinkPath = data["androidDeepLinkPath"] as? String,
            fallbackUrl = fallback,
            linkData = linkData,
        ))
    }

    // ---- warm path ---------------------------------------------------

    /** Resolve a delivered App Link. Returns false when the URI isn't Sendora-shaped. */
    fun handleAppLink(uri: Uri, onResult: ((LinkOpenedEvent?) -> Unit)? = null): Boolean {
        val shortcode = extractShortcode(uri, linkHosts) ?: run {
            onResult?.invoke(null); return false
        }
        scope.launch {
            val rich = client.requestWithDetails("GET", "/sdk/links/$shortcode", null)
            if (rich.statusCode !in 200..299) {
                withContext(Dispatchers.Main) { onResult?.invoke(null) }
                return@launch
            }
            @Suppress("UNCHECKED_CAST")
            val data = rich.body?.get("data") as? Map<String, Any?>
            if (data == null) {
                withContext(Dispatchers.Main) { onResult?.invoke(null) }
                return@launch
            }
            @Suppress("UNCHECKED_CAST")
            val linkData = (data["linkData"] as? Map<String, Any>) ?: emptyMap()
            val event = LinkOpenedEvent(
                shortcode = data["shortcode"] as? String ?: shortcode,
                linkData = linkData,
                iosDeepLinkPath = data["iosDeepLinkPath"] as? String,
                androidDeepLinkPath = data["androidDeepLinkPath"] as? String,
                isDeferred = false,
            )
            emit(event)
            withContext(Dispatchers.Main) { onResult?.invoke(event) }
        }
        return true
    }

    // ---- cold path ---------------------------------------------------

    fun matchDeferred(
        input: DeferredMatchInput = DeferredMatchInput(),
        onResult: (LinkOpenedEvent?) -> Unit,
    ) {
        scope.launch {
            var installReferrer = input.installReferrer
            var fingerprintHash = input.fingerprintHash
            if (installReferrer == null && fingerprintHash == null) {
                // Caller didn't supply anything — auto-compute the canonical fingerprint.
                // Play Install Referrer requires a peer; SDK can't probe it without the dep
                // on classpath. If the host app already retrieved the referrer, they pass it.
                fingerprintHash = computeDeviceFingerprint()
            }
            if (installReferrer == null && fingerprintHash == null) {
                withContext(Dispatchers.Main) { onResult(null) }
                return@launch
            }
            val body = buildMap<String, Any?> {
                installReferrer?.let { put("installReferrer", it) }
                fingerprintHash?.let { put("fingerprintHash", it) }
                packageName?.let { put("androidPackageName", it) }
            }
            val rich = client.requestWithDetails("POST", "/sdk/links/match", body)
            if (rich.statusCode !in 200..299) {
                withContext(Dispatchers.Main) { onResult(null) }
                return@launch
            }
            @Suppress("UNCHECKED_CAST")
            val data = rich.body?.get("data") as? Map<String, Any?>
            val shortcode = data?.get("shortcode") as? String
            if (data == null || shortcode == null) {
                withContext(Dispatchers.Main) { onResult(null) }
                return@launch
            }
            @Suppress("UNCHECKED_CAST")
            val linkData = (data["linkData"] as? Map<String, Any>) ?: emptyMap()
            val event = LinkOpenedEvent(
                shortcode = shortcode,
                linkData = linkData,
                iosDeepLinkPath = data["iosDeepLinkPath"] as? String,
                androidDeepLinkPath = data["androidDeepLinkPath"] as? String,
                isDeferred = true,
            )
            emit(event)
            withContext(Dispatchers.Main) { onResult(event) }
        }
    }

    // ---- revoke ------------------------------------------------------

    fun revoke(shortcode: String, onResult: (Result<Unit>) -> Unit) {
        if (!SHORTCODE_RE.matches(shortcode)) {
            onResult(Result.failure(LinkError(LinkErrorCode.INVALID_INPUT, "'$shortcode' is not a valid shortcode")))
            return
        }
        scope.launch {
            val rich = client.requestWithDetails("POST", "/sdk/links/$shortcode/revoke", emptyMap())
            withContext(Dispatchers.Main) {
                if (rich.statusCode in 200..299) onResult(Result.success(Unit))
                else onResult(Result.failure(mapError(rich.statusCode, rich.errorCode, rich.errorMessage)))
            }
        }
    }

    // ---- stats -------------------------------------------------------

    fun getStats(shortcode: String, onResult: (Result<LinkStats>) -> Unit) {
        if (!SHORTCODE_RE.matches(shortcode)) {
            onResult(Result.failure(LinkError(LinkErrorCode.INVALID_INPUT, "'$shortcode' is not a valid shortcode")))
            return
        }
        scope.launch {
            val rich = client.requestWithDetails("GET", "/sdk/links/$shortcode/stats", null)
            if (rich.statusCode !in 200..299) {
                withContext(Dispatchers.Main) {
                    onResult(Result.failure(mapError(rich.statusCode, rich.errorCode, rich.errorMessage)))
                }
                return@launch
            }
            @Suppress("UNCHECKED_CAST")
            val data = rich.body?.get("data") as? Map<String, Any?>
            if (data == null) {
                withContext(Dispatchers.Main) {
                    onResult(Result.failure(LinkError(LinkErrorCode.SERVER, "getStats returned an unexpected payload", rich.statusCode)))
                }
                return@launch
            }
            fun tuples(rows: List<*>, key: String): List<Pair<String?, Int>> = rows.mapNotNull { row ->
                @Suppress("UNCHECKED_CAST")
                val m = row as? Map<String, Any?> ?: return@mapNotNull null
                val k = m[key] as? String
                val c = (m["count"] as? Number)?.toInt() ?: 0
                Pair(k, c)
            }
            val stats = LinkStats(
                totalClicks = (data["totalClicks"] as? Number)?.toInt() ?: 0,
                uniqueClicks = (data["uniqueClicks"] as? Number)?.toInt() ?: 0,
                deferredMatches = (data["deferredMatches"] as? Number)?.toInt() ?: 0,
                byDevice = tuples(data["byDevice"] as? List<*> ?: emptyList<Any>(), "deviceType"),
                byCountry = tuples(data["byCountry"] as? List<*> ?: emptyList<Any>(), "country"),
                byOs = tuples(data["byOs"] as? List<*> ?: emptyList<Any>(), "os"),
            )
            withContext(Dispatchers.Main) { onResult(Result.success(stats)) }
        }
    }

    // ---- error mapping ----------------------------------------------

    private fun mapError(status: Int, code: String?, message: String?): LinkError {
        val msg = message ?: "HTTP $status"
        return when {
            status == 0 -> LinkError(LinkErrorCode.NETWORK, msg, 0)
            status == 401 || status == 403 -> LinkError(LinkErrorCode.UNAUTHORIZED, msg, status)
            status == 404 -> LinkError(LinkErrorCode.NOT_FOUND, msg, 404)
            status == 410 -> LinkError(LinkErrorCode.EXPIRED, msg, 410)
            status == 412 -> LinkError(LinkErrorCode.INVALID_INPUT, msg, 412)
            status == 429 -> LinkError(LinkErrorCode.RATE_LIMITED, msg, 429)
            status == 422 -> when {
                msg.contains("iOS bundle", true) || msg.contains("Android package", true) ->
                    LinkError(LinkErrorCode.BUNDLE_MISMATCH, msg, 422)
                msg.contains("2KB", true) || msg.contains("10KB", true) || msg.contains("linkData", true) ->
                    LinkError(LinkErrorCode.DATA_TOO_LARGE, msg, 422)
                msg.contains("fallbackUrl", true) && msg.contains("apps", true) ->
                    LinkError(LinkErrorCode.FALLBACK_REQUIRED, msg, 422)
                else -> LinkError(LinkErrorCode.INVALID_INPUT, msg, 422)
            }
            status == 402 || code == "ENTITLEMENT_ERROR" || msg.contains("plan limit", true) ->
                LinkError(LinkErrorCode.PLAN_LIMIT, msg, status)
            status >= 500 -> LinkError(LinkErrorCode.SERVER, msg, status)
            else -> LinkError(LinkErrorCode.UNKNOWN, msg, status)
        }
    }

    companion object {
        private val SHORTCODE_RE = Regex("^[a-z0-9-]{3,20}$")

        /**
         * Extract a shortcode from a Sendora URI.
         * When [allowedHosts] is non-empty, the URI's host must equal an
         * entry or be a subdomain. When empty: host-agnostic (back-compat).
         */
        @JvmStatic
        fun extractShortcode(uri: Uri, allowedHosts: List<String> = emptyList()): String? {
            if (allowedHosts.isNotEmpty()) {
                val host = uri.host?.lowercase() ?: return null
                val ok = allowedHosts.any { a ->
                    val low = a.lowercase()
                    host == low || host.endsWith(".$low")
                }
                if (!ok) return null
            }
            val segs = uri.pathSegments.filter { it.isNotEmpty() }
            val tail = when {
                segs.size >= 2 && segs[0] == "link" -> segs[1]
                segs.size == 1 -> segs[0]
                segs.isNotEmpty() -> segs.last()
                else -> null
            } ?: return null
            return if (SHORTCODE_RE.matches(tail)) tail else null
        }

        /**
         * Canonical device-fingerprint recipe matching iOS + React Native.
         * Input: `${platform}|${screenW}x${screenH}|${timezone}|${locale}`.
         * Output: lowercase hex SHA-256 (64 chars).
         */
        @JvmStatic
        fun computeDeviceFingerprint(): String {
            val metrics = Resources.getSystem().displayMetrics
            val screen = "${metrics.widthPixels}x${metrics.heightPixels}"
            val tz = TimeZone.getDefault().id
            val locale = Locale.getDefault().toString()
            val input = "android|$screen|$tz|$locale"
            val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }
    }
}
