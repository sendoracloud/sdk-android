package com.sendoracloud.sdk

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import com.sendoracloud.sdk.internal.AuthTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URLEncoder

/**
 * Wave 66 — Contact widget for Android apps.
 *
 * Opens the worker-hosted embed at
 * `https://go.sendoracloud.com/embed/contact?widgetId=…` inside a
 * WebView wrapped in a transparent Activity. The HTML form posts to
 * `POST /widgets/:id/submit` server-side — same backend the web
 * widget.js uses.
 *
 * On submit success the page navigates to
 * `sendora://close?ticketId=…&portalUrl=…`. WebViewClient catches
 * the scheme, finishes the Activity, and broadcasts the result back
 * to the host via a static callback (the simplest cross-Activity
 * channel that doesn't force the host to wire `onActivityResult`).
 *
 * 4.27.0 (s58.376, parity RN 1.42.0 / iOS 5.5.0):
 *  - [createTicket] sends the signed-in player's access token, so the ticket carries their VERIFIED user id;
 *  - [listMyTickets] / [getMyTicket] / [replyToMyTicket] — the player's own conversations for a native support
 *    screen; refusals throw [SendoraSupportException] (never an empty list);
 *  - [deviceContext] — app version + build, OS + version, device model, SDK version;
 *  - the contact widget takes `metadata`, `includeDeviceContext`, `attachSession`, `accent`; the token and the
 *    metadata ride the URL FRAGMENT (no server logs it).
 * Support calls now use the CONFIGURED API base URL through the SDK's client (they always went to production).
 */
class SendoraCloudSupport internal constructor(
    private val widgetEmbedHost: String = "https://go.sendoracloud.com",
    /** Seams for tests; production reads the configured SDK. */
    private val transportProvider: () -> AuthTransport? = { SendoraCloud.supportTransport() },
    private val tokenProvider: suspend () -> String? = { SendoraCloud.auth?.getAccessToken() },
    private val contextProvider: () -> Map<String, Any?> = { SendoraCloud.supportDeviceContext() },
) {
    private val supportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // ── Metadata + device context (4.27.0) ─────────────────────────────

    /** App version + build, OS + version, device model and SDK version — merge into [createTicket]'s metadata. */
    fun deviceContext(): Map<String, Any?> = contextProvider()

    companion object {
        private val KEY_RE = Regex("^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
        private val HEX_RE = Regex("^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

        /**
         * The backend's metadata rules, applied on the device so a bad entry never costs the player their message
         * (the server refuses the whole ticket with a 422): ≤ 30 keys of letters, digits, space, `_ . -` (max 64),
         * values String (≤ 1000 chars) / finite number / Boolean / null. Anything else is DROPPED. Keys are taken in
         * sorted order so the cap is deterministic (parity iOS).
         */
        @JvmStatic
        fun sanitizeMetadata(input: Map<String, Any?>?): Map<String, Any?> {
            if (input == null) return emptyMap()
            val out = LinkedHashMap<String, Any?>()
            for (key in input.keys.sorted()) {
                if (out.size >= 30) break
                if (!KEY_RE.matches(key)) continue
                when (val v = input[key]) {
                    null -> out[key] = null
                    is String -> out[key] = v.take(1000)
                    is Boolean -> out[key] = v
                    is Double -> if (v.isFinite()) out[key] = v
                    is Float -> if (v.isFinite()) out[key] = v
                    is Number -> out[key] = v
                    else -> {}
                }
            }
            return out
        }

        internal fun isHexColor(s: String?): Boolean = s != null && HEX_RE.matches(s)

        /** `URLSearchParams`-compatible encoding (space → `+`, `+` → `%2B`), used for the query and the fragment. */
        private fun enc(v: String): String = URLEncoder.encode(v, "UTF-8")

        /**
         * The hosted contact form's URL. Token + metadata go in the FRAGMENT (no server sees or logs it); the accent
         * in the query only when it is a hex colour.
         */
        internal fun contactUrl(
            host: String,
            widgetId: String,
            theme: String,
            prefillName: String?,
            prefillEmail: String?,
            prefillUserId: String?,
            lockEmail: Boolean,
            accent: String?,
            accessToken: String?,
            metadata: Map<String, Any?>,
        ): String {
            val q = mutableListOf("widgetId=${enc(widgetId)}", "theme=${enc(theme)}")
            if (!prefillName.isNullOrBlank()) q += "prefillName=${enc(prefillName)}"
            if (!prefillEmail.isNullOrBlank()) q += "prefillEmail=${enc(prefillEmail)}"
            if (!prefillUserId.isNullOrBlank()) q += "prefillUserId=${enc(prefillUserId)}"
            if (lockEmail && !prefillEmail.isNullOrBlank()) q += "lockEmail=1"
            if (isHexColor(accent)) q += "accent=${enc(accent!!)}"
            val frag = mutableListOf<String>()
            if (!accessToken.isNullOrBlank()) frag += "access=${enc(accessToken)}"
            if (metadata.isNotEmpty()) frag += "metadata=${enc(JSONObject(metadata).toString())}"
            val base = "$host/embed/contact?" + q.joinToString("&")
            return if (frag.isEmpty()) base else base + "#" + frag.joinToString("&")
        }

        private fun pathSegment(v: String): String = enc(v).replace("+", "%20")
        internal fun myTicketsPath(widgetId: String): String = "/widgets/${pathSegment(widgetId)}/my-tickets"
    }

    // ── API (4.27.0) ───────────────────────────────────────────────────

    private fun transport(): AuthTransport =
        transportProvider() ?: throw SendoraSupportException("NOT_CONFIGURED", 0, "SendoraCloud.init() must run first.")

    private suspend fun bearer(verb: String): Map<String, String> {
        val token = runCatching { tokenProvider() }.getOrNull()
        if (token.isNullOrBlank()) {
            throw SendoraSupportException("NOT_SIGNED_IN", 401, "support.$verb() needs a signed-in (or guest) session.")
        }
        return mapOf("Authorization" to "Bearer $token")
    }

    /** Unwrap `{ success, data }` or throw the server's refusal — never an empty answer for a failure. */
    @Suppress("UNCHECKED_CAST")
    private fun data(json: Map<String, Any?>?, verb: String): Any {
        if (json == null) throw SendoraSupportException("NETWORK", 0, "support.$verb() could not reach the server.")
        val d = json["data"]
        if (json["success"] == true && d != null) return d
        val error = json["error"] as? Map<String, Any?>
        val status = (error?.get("status") as? Number)?.toInt() ?: 0
        throw SendoraSupportException(
            error?.get("code") as? String ?: "HTTP_$status",
            status,
            error?.get("message") as? String ?: "support.$verb() failed ($status)",
        )
    }

    private fun Map<String, Any?>.str(k: String): String = this[k] as? String ?: ""

    @Suppress("UNCHECKED_CAST")
    private fun asMap(v: Any, verb: String): Map<String, Any?> =
        v as? Map<String, Any?> ?: throw SendoraSupportException("BAD_RESPONSE", 0, "support.$verb(): unexpected response")

    /**
     * Open a ticket from your own Contact-us screen. Signed in (guest or account), the player's token is sent, so the
     * ticket carries their VERIFIED user id; without a session it is still created and a [userId] you pass is shown
     * to agents as "reported by the app, not verified". [metadata]: see [sanitizeMetadata] / [deviceContext].
     */
    suspend fun createTicket(
        subject: String,
        body: String,
        priority: String? = null,
        category: String? = null,
        email: String? = null,
        userId: String? = null,
        metadata: Map<String, Any?>? = null,
    ): SendoraCreatedTicket {
        val payload = mutableMapOf<String, Any?>("subject" to subject, "body" to body)
        priority?.let { payload["priority"] = it }
        category?.let { payload["category"] = it }
        email?.let { payload["email"] = it }
        userId?.let { payload["userId"] = it }
        metadata?.let { payload["metadata"] = sanitizeMetadata(it) }
        val token = runCatching { tokenProvider() }.getOrNull()
        val headers = if (token.isNullOrBlank()) null else mapOf("Authorization" to "Bearer $token")
        val d = asMap(data(transport().post("/support/tickets", payload, headers), "createTicket"), "createTicket")
        return SendoraCreatedTicket(d.str("id"), d.str("subject"), d.str("status"), d.str("priority"), d["userIdVerified"] == true)
    }

    /**
     * The signed-in player's tickets (newest activity first, up to 50). [widgetId] = a contact widget of THIS app's
     * project. Throws [SendoraSupportException] (`NOT_SIGNED_IN`, `PROJECT_MISMATCH`, …).
     */
    suspend fun listMyTickets(widgetId: String): List<SendoraMyTicketSummary> {
        val headers = bearer("listMyTickets")
        val rows = data(transport().get(myTicketsPath(widgetId), headers), "listMyTickets") as? List<*>
            ?: throw SendoraSupportException("BAD_RESPONSE", 0, "support.listMyTickets(): unexpected response")
        return rows.filterIsInstance<Map<*, *>>().map {
            @Suppress("UNCHECKED_CAST") val o = it as Map<String, Any?>
            SendoraMyTicketSummary(o.str("id"), o.str("subject"), o.str("status"), o.str("priority"),
                o.str("createdAt"), o.str("updatedAt"), o["resolvedAt"] as? String, o["unread"] == true)
        }
    }

    /** One ticket with its public replies (internal notes are never returned). Marks it read. */
    suspend fun getMyTicket(widgetId: String, ticketId: String): SendoraMyTicket {
        val headers = bearer("getMyTicket")
        val d = asMap(data(transport().get(myTicketsPath(widgetId) + "/" + pathSegment(ticketId), headers), "getMyTicket"), "getMyTicket")
        val replies = (d["replies"] as? List<*> ?: emptyList<Any?>()).filterIsInstance<Map<*, *>>().map {
            @Suppress("UNCHECKED_CAST") val r = it as Map<String, Any?>
            SendoraMyTicketReply(r.str("id"), r.str("body"), r.str("authorType"), r.str("createdAt"))
        }
        return SendoraMyTicket(d.str("id"), d.str("subject"), d.str("body"), d.str("status"), d.str("priority"),
            d.str("createdAt"), d.str("updatedAt"), d["resolvedAt"] as? String, replies)
    }

    /** The player replies. A resolved / closed ticket reopens (`reopened == true`). */
    suspend fun replyToMyTicket(widgetId: String, ticketId: String, body: String): SendoraTicketReplyResult {
        val headers = bearer("replyToMyTicket")
        val path = myTicketsPath(widgetId) + "/" + pathSegment(ticketId) + "/replies"
        val d = asMap(data(transport().post(path, mapOf("body" to body), headers), "replyToMyTicket"), "replyToMyTicket")
        return SendoraTicketReplyResult(d.str("id"), d.str("createdAt"), d["reopened"] == true)
    }

    /**
     * Wave 73 — fetch the unread ticket count for the support tab
     * badge. Bearer JWT auth via the SDK's current end-user session.
     * Returns 0 when no SDK auth exists, or on any failure (safe to poll).
     *
     * Suspends — call from a coroutine. Recommended cadence: on app
     * foreground + every 60s while the app is active. Host app
     * renders the count as a tab badge / dot.
     */
    suspend fun getUnreadCount(widgetId: String): Int {
        if (widgetId.isBlank()) return 0
        val token = runCatching { tokenProvider() }.getOrNull()
        if (token.isNullOrBlank()) return 0
        // 4.27.0: through the SDK's client = the CONFIGURED API base (this always went to production).
        val client = transportProvider() ?: return 0
        val json = runCatching { client.get(myTicketsPath(widgetId) + "/unread-count", mapOf("Authorization" to "Bearer $token")) }
            .getOrNull() ?: return 0
        if (json["success"] != true) return 0
        @Suppress("UNCHECKED_CAST")
        return ((json["data"] as? Map<String, Any?>)?.get("count") as? Number)?.toInt() ?: 0
    }

    /**
     * Open the in-app ticket history list (Wave 69).
     *
     * Requires an active SDK auth session (anon or identified). Reads
     * the current access token via `SendoraCloud.auth.getAccessToken()`
     * and passes it as the URL fragment so the embed can call backend
     * `/widgets/:widgetId/my-tickets*` endpoints as the signed-in
     * end user.
     *
     * Fires [onResult] with `submitted=false, ticketId=""` if the SDK
     * has no auth session (matches the "user closed without action"
     * shape so the host doesn't need to special-case).
     *
     * [accent]: 4.27.0 — `#rgb` / `#rrggbb`; default = the widget's dashboard accent.
     */
    fun presentTicketHistory(
        activity: Activity,
        widgetId: String,
        theme: String = "auto",
        accent: String? = null,
        onResult: ((SendoraContactResult) -> Unit)? = null,
    ) {
        if (widgetId.isBlank()) {
            onResult?.invoke(SendoraContactResult("", null, false))
            return
        }
        if (SendoraCloud.auth == null) {
            onResult?.invoke(SendoraContactResult("", null, false))
            return
        }

        supportScope.launch {
            val token = runCatching { tokenProvider() }.getOrNull()
            withContext(Dispatchers.Main) {
                if (token.isNullOrBlank()) {
                    onResult?.invoke(SendoraContactResult("", null, false))
                    return@withContext
                }

                val uri = Uri.parse("$widgetEmbedHost/embed/tickets").buildUpon()
                    .appendQueryParameter("widgetId", widgetId)
                    .appendQueryParameter("theme", theme)
                    .apply { if (isHexColor(accent)) appendQueryParameter("accent", accent) }
                    .build()
                    .toString() + "#access=" + URLEncoder.encode(token, "UTF-8")

                SendoraContactWidgetActivity.pendingCallback = onResult
                val intent = Intent(activity, SendoraContactWidgetActivity::class.java).apply {
                    putExtra(SendoraContactWidgetActivity.EXTRA_URL, uri)
                }
                activity.startActivity(intent)
            }
        }
    }
    /**
     * Open the contact widget over [activity].
     *
     * Identity handling (Wave 68): when [prefillEmail] / [prefillUserId] /
     * [lockEmail] are null, auto-reads `SendoraCloud.auth?.currentUser`:
     *
     *   - identified user with verified email → email field hidden,
     *     read-only chip shown, `userId` posted with the ticket so it
     *     stitches to the same profile as analytics events.
     *   - anonymous SDK row (userId only, no email) → email field shown,
     *     anon `userId` posted.
     *   - no SDK auth → standard form, no `userId`.
     *
     * 4.27.0: [metadata] — extra details for your agents ("details from the app"; invalid entries are dropped, never
     * block the player); [includeDeviceContext] attaches [deviceContext] (your keys win); [attachSession] sends the
     * player's token so the ticket carries their VERIFIED user id (a missing token still opens the form); [accent]
     * `#rgb` / `#rrggbb`.
     *
     * [onResult] is fired on the main thread when the user closes the
     * sheet — either after a successful submit (`submitted = true`) or
     * via close button / back gesture (`submitted = false`).
     */
    fun presentContactWidget(
        activity: Activity,
        widgetId: String,
        theme: String = "auto",
        prefillName: String? = null,
        prefillEmail: String? = null,
        prefillUserId: String? = null,
        lockEmail: Boolean? = null,
        metadata: Map<String, Any?>? = null,
        includeDeviceContext: Boolean = true,
        attachSession: Boolean = true,
        accent: String? = null,
        onResult: ((SendoraContactResult) -> Unit)? = null,
    ) {
        if (widgetId.isBlank()) {
            onResult?.invoke(SendoraContactResult(ticketId = "", portalUrl = null, submitted = false))
            return
        }

        val sdkUser = SendoraCloud.auth?.currentUser
        val resolvedName = prefillName ?: sdkUser?.name
        val resolvedEmail = prefillEmail ?: sdkUser?.email
        val resolvedUserId = prefillUserId ?: sdkUser?.id
        val resolvedLockEmail = lockEmail ?: (
            sdkUser?.email != null
                && sdkUser.emailVerified
                && !sdkUser.isAnonymous
            )
        val merged = LinkedHashMap<String, Any?>()
        if (includeDeviceContext) merged.putAll(deviceContext())
        metadata?.let { merged.putAll(it) }
        val context = sanitizeMetadata(merged)

        val open: (String?) -> Unit = { token ->
            val uri = contactUrl(widgetEmbedHost, widgetId, theme, resolvedName, resolvedEmail, resolvedUserId,
                resolvedLockEmail, accent, token, context)
            // Stash the callback in a static slot — Activity reads it on
            // close. Static is fine here because we only allow one open
            // sheet at a time (subsequent calls overwrite, matching the
            // single-modal posture of the iOS counterpart).
            SendoraContactWidgetActivity.pendingCallback = onResult
            val intent = Intent(activity, SendoraContactWidgetActivity::class.java).apply {
                putExtra(SendoraContactWidgetActivity.EXTRA_URL, uri)
            }
            activity.startActivity(intent)
        }
        if (!attachSession) {
            open(null)
            return
        }
        supportScope.launch {
            // A token problem never keeps the player from reaching support.
            val token = runCatching { tokenProvider() }.getOrNull()
            withContext(Dispatchers.Main) { open(token) }
        }
    }
}

/** 4.27.0 — a refused support call: the server's `code` (`PROJECT_MISMATCH`, …) or `NOT_SIGNED_IN` / `NETWORK` / … */
class SendoraSupportException(val code: String, val status: Int, message: String) : Exception(message)

/** 4.27.0 — one of the player's tickets ([SendoraCloudSupport.listMyTickets]). */
data class SendoraMyTicketSummary(
    val id: String,
    val subject: String,
    /** `open` → `pending` → `resolved` / `closed`. */
    val status: String,
    val priority: String,
    /** ISO-8601. */
    val createdAt: String,
    /** ISO-8601 — the last activity. */
    val updatedAt: String,
    val resolvedAt: String?,
    /** Activity the player has not opened yet ([SendoraCloudSupport.getMyTicket] clears it). */
    val unread: Boolean,
)

/** 4.27.0 — a public reply. `authorType`: `customer` (the player) or `agent` (your team). */
data class SendoraMyTicketReply(val id: String, val body: String, val authorType: String, val createdAt: String)

/** 4.27.0 — one ticket with its public replies (internal notes are never returned). */
data class SendoraMyTicket(
    val id: String,
    val subject: String,
    /** The player's first message. */
    val body: String,
    val status: String,
    val priority: String,
    val createdAt: String,
    val updatedAt: String,
    val resolvedAt: String?,
    val replies: List<SendoraMyTicketReply>,
)

/** 4.27.0 — the result of [SendoraCloudSupport.replyToMyTicket]. */
data class SendoraTicketReplyResult(val id: String, val createdAt: String, val reopened: Boolean)

/** 4.27.0 — the result of [SendoraCloudSupport.createTicket]. */
data class SendoraCreatedTicket(
    val id: String,
    val subject: String,
    val status: String,
    val priority: String,
    /** True when the ticket's user id came from the player's signed-in session. */
    val userIdVerified: Boolean,
)

data class SendoraContactResult(
    /** UUID of the ticket created server-side, or empty if user closed without submitting. */
    val ticketId: String,
    /** Operator's tracking-portal URL (Uri) when submitted, null otherwise. */
    val portalUrl: Uri?,
    /** True if the user submitted the form; false if they closed without submitting. */
    val submitted: Boolean,
)

// ───────────────────────────────────────────────────────────────────
// Internal Activity — programmatic UI, no XML layout to avoid forcing
// resource generation on host apps.
// ───────────────────────────────────────────────────────────────────

class SendoraContactWidgetActivity : Activity() {
    private var webView: WebView? = null
    private var didFire = false

    companion object {
        const val EXTRA_URL = "com.sendoracloud.support.url"

        // Single pending callback — overwritten on each present() call.
        // Cleared on Activity.onDestroy so the host doesn't hold a
        // reference longer than the sheet's lifetime.
        @JvmStatic
        internal var pendingCallback: ((SendoraContactResult) -> Unit)? = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val container = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
        }
        setContentView(container)

        val wv = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            // Force-fit viewport — the embed page sets its own
            // initial-scale + safe-area handling.
            settings.loadWithOverviewMode = true
            settings.useWideViewPort = true
            visibility = View.VISIBLE
            webViewClient = SendoraContactWebViewClient { url ->
                fireCloseFromUri(url)
            }
        }
        container.addView(
            wv,
            ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ),
        )
        webView = wv

        val url = intent.getStringExtra(EXTRA_URL)
        if (url.isNullOrBlank()) {
            finishWithResult(SendoraContactResult("", null, false))
            return
        }
        wv.loadUrl(url)
    }

    override fun onBackPressed() {
        // Back button = user closed without submitting.
        finishWithResult(SendoraContactResult("", null, false))
    }

    private fun fireCloseFromUri(uri: Uri) {
        val ticketId = uri.getQueryParameter("ticketId") ?: ""
        val portalUrlStr = uri.getQueryParameter("portalUrl") ?: ""
        val portalUrl = if (portalUrlStr.isBlank()) null else Uri.parse(portalUrlStr)
        finishWithResult(SendoraContactResult(ticketId, portalUrl, submitted = ticketId.isNotEmpty()))
    }

    private fun finishWithResult(result: SendoraContactResult) {
        if (didFire) return
        didFire = true
        val cb = pendingCallback
        pendingCallback = null
        // Hand back on main thread (we're already on the UI thread here).
        cb?.invoke(result)
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        webView?.destroy()
        webView = null
    }
}

internal class SendoraContactWebViewClient(
    private val onClose: (Uri) -> Unit,
) : WebViewClient() {

    override fun shouldOverrideUrlLoading(view: WebView?, url: String?): Boolean {
        if (url == null) return false
        return handle(Uri.parse(url))
    }

    override fun shouldOverrideUrlLoading(
        view: WebView?,
        request: android.webkit.WebResourceRequest?,
    ): Boolean {
        val uri = request?.url ?: return false
        return handle(uri)
    }

    private fun handle(uri: Uri): Boolean {
        if (uri.scheme == "sendora" && uri.host == "close") {
            onClose(uri)
            return true
        }
        // First-party HTTPS only — refuse off-domain navigations
        // inside the embed (e.g. if a customer-supplied welcome
        // message somehow included a link).
        return uri.scheme != "https" && uri.scheme != "about"
    }
}
