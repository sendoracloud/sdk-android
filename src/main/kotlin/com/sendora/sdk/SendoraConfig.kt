package com.sendora.sdk

/** Configuration for the Sendora SDK. */
data class SendoraConfig(
    val apiKey: String,
    val projectId: String,
    val apiBaseUrl: String = "https://api.sendoracloud.com",
    val flushInterval: Long = 30_000L,
    val flushAt: Int = 20,
    val maxQueueSize: Int = 1000,
    val debug: Boolean = false,
    /** Host allowlist for `handleDeepLink`. Defaults to sendoracloud.com. */
    val linkHosts: List<String> = listOf("sendoracloud.com"),
    /**
     * When false (default), analytics events are buffered until
     * `Sendora.consent.grant()` is called. Flip to true if you've already
     * gathered consent outside the SDK.
     */
    val defaultConsent: Boolean = false,
    /**
     * Auto-start install reporting + session tracking. Set to false for
     * strict privacy-prompt-first flows.
     */
    val autoStartAttribution: Boolean = true,
)

/** HMAC identity-token options for `identify()`. */
data class SendoraIdentifyOptions(
    /**
     * HMAC of `userId` signed by your backend with your server-side secret.
     * Required when the project is in strict-identity mode — the backend
     * verifies the HMAC, blocking identity spoofing from client code.
     */
    val identityToken: String? = null,
)
