package com.sendoracloud.sdk

/** Configuration for the SendoraCloud SDK. */
data class SendoraCloudConfig(
    val apiKey: String,
    val projectId: String,
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
