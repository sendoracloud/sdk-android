package com.sendoracloud.sdk

import android.net.Uri
import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.SendoraCloudLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Deep-link surface for the Android SDK. Mirrors `Sendora.links` on
 * iOS + React Native. Three core moves:
 *   • [create]              — mint a Sendora short link from inside the app
 *                             (Pulse-style "share article" UX).
 *   • [handleAppLink]       — call from `Activity.onCreate` / `onNewIntent`
 *                             to resolve a warm-path Android App Link delivery
 *                             into a [LinkOpenedEvent].
 *   • [matchDeferred]       — call once on cold launch w/ Play Install Referrer
 *                             (preferred — 100% accurate) and/or a precomputed
 *                             fingerprint hash (fallback). Fires `onLinkOpened`
 *                             with `isDeferred = true` on a successful match.
 *
 * Use [onLinkOpened] to register a callback fired for both warm + deferred
 * events. Multiple callbacks supported. Returns an opaque token usable with
 * [removeLinkOpenedHandler] to unsubscribe.
 */
class SendoraCloudLinks internal constructor(
    private val client: ApiClient,
    private val packageName: String?,
    private val scope: CoroutineScope,
) {
    data class LinkCreateInput(
        val title: String,
        val fallbackUrl: String,
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
        /** Fully-qualified share URL — pass to `Intent.ACTION_SEND` for the share sheet. */
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

    // ---- create ------------------------------------------------------

    fun create(
        input: LinkCreateInput,
        onResult: (Result<LinkCreateResult>) -> Unit,
    ) {
        if (input.title.isEmpty()) {
            onResult(Result.failure(IllegalArgumentException("title is required")))
            return
        }
        if (input.fallbackUrl.isEmpty()) {
            onResult(Result.failure(IllegalArgumentException("fallbackUrl is required")))
            return
        }
        scope.launch {
            val body = buildMap<String, Any?> {
                put("title", input.title)
                put("fallbackUrl", input.fallbackUrl)
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
            val response = client.post("/sdk/links", body)
            @Suppress("UNCHECKED_CAST")
            val data = response?.get("data") as? Map<String, Any?>
            val id = data?.get("id") as? String
            val shortcode = data?.get("shortcode") as? String
            val url = data?.get("url") as? String
            val fallback = data?.get("fallbackUrl") as? String

            withContext(Dispatchers.Main) {
                if (id == null || shortcode == null || url == null || fallback == null) {
                    onResult(Result.failure(RuntimeException("links.create returned an unexpected payload")))
                } else {
                    @Suppress("UNCHECKED_CAST")
                    val linkData = (data["linkData"] as? Map<String, Any>) ?: emptyMap()
                    onResult(Result.success(LinkCreateResult(
                        id = id,
                        shortcode = shortcode,
                        url = url,
                        iosDeepLinkPath = data["iosDeepLinkPath"] as? String,
                        androidDeepLinkPath = data["androidDeepLinkPath"] as? String,
                        fallbackUrl = fallback,
                        linkData = linkData,
                    )))
                }
            }
        }
    }

    // ---- warm path ---------------------------------------------------

    /**
     * Resolve an Android App Link delivery + fire [onLinkOpened]. Returns
     * `false` if the URI doesn't parse as a Sendora link; `true` if a
     * resolve call was kicked off (callback fires async on the main thread).
     */
    fun handleAppLink(uri: Uri, onResult: ((LinkOpenedEvent?) -> Unit)? = null): Boolean {
        val shortcode = extractShortcode(uri) ?: run {
            onResult?.invoke(null)
            return false
        }
        scope.launch {
            val response = client.get("/sdk/links/${shortcode}")
            @Suppress("UNCHECKED_CAST")
            val data = response?.get("data") as? Map<String, Any?>
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

    data class DeferredMatchInput(
        /**
         * Raw output of `PlayInstallReferrerClient.getInstallReferrer().installReferrer`.
         * Preferred input — 100% accurate when present.
         */
        val installReferrer: String? = null,
        /**
         * Optional fallback fingerprint hash (hex SHA-256 of ip+ua+screen+tz).
         * Probabilistic match (~80-90% accuracy). Useful when Play Install
         * Referrer is missing (sideloaded APK, China stores).
         */
        val fingerprintHash: String? = null,
    )

    fun matchDeferred(input: DeferredMatchInput, onResult: (LinkOpenedEvent?) -> Unit) {
        if (input.installReferrer == null && input.fingerprintHash == null) {
            onResult(null); return
        }
        scope.launch {
            val body = buildMap<String, Any?> {
                input.installReferrer?.let { put("installReferrer", it) }
                input.fingerprintHash?.let { put("fingerprintHash", it) }
                packageName?.let { put("androidPackageName", it) }
            }
            val response = client.post("/sdk/links/match", body)
            @Suppress("UNCHECKED_CAST")
            val data = response?.get("data") as? Map<String, Any?>
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

    companion object {
        private val SHORTCODE_RE = Regex("^[a-z0-9-]{3,20}$")

        /**
         * Extract a shortcode from a Sendora link URI. Accepts:
         *   • `https://go.sendoracloud.com/<shortcode>`
         *   • `https://go.sendoracloud.com/link/<shortcode>` (Worker rewrite)
         * Returns `null` for malformed input.
         */
        @JvmStatic
        fun extractShortcode(uri: Uri): String? {
            val segs = uri.pathSegments.filter { it.isNotEmpty() }
            val tail = when {
                segs.size >= 2 && segs[0] == "link" -> segs[1]
                segs.size == 1 -> segs[0]
                else -> null
            } ?: return null
            return if (SHORTCODE_RE.matches(tail)) tail else null
        }
    }
}
