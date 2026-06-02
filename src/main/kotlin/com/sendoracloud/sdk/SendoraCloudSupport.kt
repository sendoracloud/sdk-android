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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
 * Single source of truth = the worker route. Updating contact form
 * UI = redeploy worker. Zero SDK release.
 */
class SendoraCloudSupport internal constructor(
    private val widgetEmbedHost: String = "https://go.sendoracloud.com",
    private val apiBaseUrl: String = "https://api.sendoracloud.com",
) {
    private val supportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Wave 73 — fetch the unread ticket count for the support tab
     * badge. Bearer JWT auth via the SDK's current end-user session.
     * Returns 0 when no SDK auth exists.
     *
     * Suspends — call from a coroutine. Recommended cadence: on app
     * foreground + every 60s while the app is active. Host app
     * renders the count as a tab badge / dot.
     */
    suspend fun getUnreadCount(widgetId: String): Int {
        if (widgetId.isBlank()) return 0
        val auth = SendoraCloud.auth ?: return 0
        val token = auth.getAccessToken()
        if (token.isNullOrBlank()) return 0

        return withContext(Dispatchers.IO) {
            try {
                val url = java.net.URL("$apiBaseUrl/api/v1/widgets/$widgetId/my-tickets/unread-count")
                val conn = url.openConnection() as java.net.HttpURLConnection
                conn.setRequestProperty("Authorization", "Bearer $token")
                conn.connectTimeout = 10_000
                conn.readTimeout = 10_000
                val code = conn.responseCode
                if (code !in 200..299) {
                    conn.disconnect()
                    return@withContext 0
                }
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                conn.disconnect()
                // Tiny parse — avoid pulling in a JSON dep. Body shape
                // is `{"success":true,"data":{"count":N}}`.
                val match = Regex("\"count\"\\s*:\\s*(\\d+)").find(body)
                match?.groupValues?.getOrNull(1)?.toIntOrNull() ?: 0
            } catch (_: Exception) {
                0
            }
        }
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
     */
    fun presentTicketHistory(
        activity: Activity,
        widgetId: String,
        theme: String = "auto",
        onResult: ((SendoraContactResult) -> Unit)? = null,
    ) {
        if (widgetId.isBlank()) {
            onResult?.invoke(SendoraContactResult("", null, false))
            return
        }
        val auth = SendoraCloud.auth
        if (auth == null) {
            onResult?.invoke(SendoraContactResult("", null, false))
            return
        }

        supportScope.launch {
            val token = auth.getAccessToken()
            withContext(Dispatchers.Main) {
                if (token.isNullOrBlank()) {
                    onResult?.invoke(SendoraContactResult("", null, false))
                    return@withContext
                }

                val uri = Uri.parse("$widgetEmbedHost/embed/tickets").buildUpon()
                    .appendQueryParameter("widgetId", widgetId)
                    .appendQueryParameter("theme", theme)
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

        val uri = Uri.parse("$widgetEmbedHost/embed/contact").buildUpon()
            .appendQueryParameter("widgetId", widgetId)
            .appendQueryParameter("theme", theme)
            .apply {
                if (!resolvedName.isNullOrBlank()) appendQueryParameter("prefillName", resolvedName)
                if (!resolvedEmail.isNullOrBlank()) appendQueryParameter("prefillEmail", resolvedEmail)
                if (!resolvedUserId.isNullOrBlank()) appendQueryParameter("prefillUserId", resolvedUserId)
                if (resolvedLockEmail && !resolvedEmail.isNullOrBlank()) {
                    appendQueryParameter("lockEmail", "1")
                }
            }
            .build()
            .toString()

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
}

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
