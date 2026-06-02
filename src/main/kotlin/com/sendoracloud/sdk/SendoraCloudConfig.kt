package com.sendoracloud.sdk

/** Configuration for the SendoraCloud SDK. */
data class SendoraCloudConfig(
    val apiKey: String,
    /**
     * Project UUID. Optional as of 3.0.0 — when null the backend
     * derives project + org + environment from the API key row
     * server-side (matches sdk-web 2.7.0 behaviour). Pre-3.0.0
     * callers passing a value still work; the field is surfaced on
     * every event payload for backwards compatibility.
     */
    val projectId: String? = null,
    val apiBaseUrl: String = "https://api.sendoracloud.com",
    val flushInterval: Long = 30_000L,
    val flushAt: Int = 20,
    val maxQueueSize: Int = 1000,
    val debug: Boolean = false,
    /** Host allowlist for `handleDeepLink`. Defaults to the redirect zone
     *  + the marketing domain (the latter for legacy compat — most
     *  customer deep-links land on go.sendoracloud.com). */
    val linkHosts: List<String> = listOf("go.sendoracloud.com", "sendoracloud.com"),
    /**
     * When false (default), analytics events are buffered until
     * `SendoraCloud.consent.grant()` is called. Flip to true if you've already
     * gathered consent outside the SDK.
     */
    val defaultConsent: Boolean = false,
    /**
     * Auto-start install reporting + session tracking. Set to false for
     * strict privacy-prompt-first flows.
     */
    val autoStartAttribution: Boolean = true,
    /**
     * Optional certificate-pinning set. When non-empty, the SDK enforces
     * that the server's leaf-certificate Subject Public Key Info SHA-256
     * matches one of the supplied base64 hashes — an attacker-installed
     * enterprise CA can no longer MitM auth tokens. Compute with:
     * `openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin
     * -outform der | openssl dgst -sha256 -binary | openssl base64`.
     * Always include at least one backup pin. Default: empty (system
     * trust only).
     */
    val pinnedSPKIHashes: List<String> = emptyList(),
    /**
     * Auto-collect lifecycle events. Mirrors Firebase Analytics' auto-collected
     * surface: `app.opened` (per launch), `app.foregrounded` /
     * `app.backgrounded` (ProcessLifecycleOwner transitions), `session.start` /
     * `session.end` (launch-bounded). Default: true. Set to false to opt
     * out — useful when the host app already wires its own lifecycle
     * telemetry.
     */
    val autoTrackLifecycle: Boolean = true,
    /**
     * Auto-measure foreground engagement time per screen. When true (default),
     * `trackScreen(name)` emits an `app.engagement` event carrying
     * foreground-only `durationMs` for the previously-viewed screen. Time
     * while the app is backgrounded is never counted (GA4 engagement_time_msec
     * model). Only measures screens you name via `trackScreen(name)` — there
     * is no Activity/Fragment auto-instrumentation, so screen names stay clean.
     */
    val autoTrackEngagement: Boolean = true,
)

/** HMAC identity-token options for `identify()`. */
data class SendoraCloudIdentifyOptions(
    /**
     * HMAC of `userId` signed by your backend with your server-side secret.
     * Required when the project is in strict-identity mode — the backend
     * verifies the HMAC, blocking identity spoofing from client code.
     */
    val identityToken: String? = null,
)
