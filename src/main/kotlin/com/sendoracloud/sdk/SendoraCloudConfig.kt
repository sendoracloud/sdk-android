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
    /**
     * ADR-033 wave 1 (4.26.0) — opt-in PROJECT GUARD. When set, every session the
     * SDK is about to install (a stored one at hydrate, a refresh result, a fresh
     * mint / sign-in, a restored held guest) is judged by its JWT `project`
     * claim BEFORE anything is assigned. A STORED session whose claim disagrees
     * is not wiped and not used: `auth.status()` reports [AuthStatus.WITHHELD],
     * every verb rejects `SESSION_WITHHELD` (kind CONFIG), and the exits are
     * `auth.discardWithheld()` or relaunching with the matching key. A FRESH
     * mint / sign-in that answers with the wrong project is refused with
     * `PROJECT_MISMATCH` and its tokens revoked — the wrong-key build fails at
     * first launch instead of poisoning a device.
     *
     * Must be a canonical UUID and, when [projectId] is also set, equal to it
     * (`init` throws otherwise). Advisory — a client consistency check, not an
     * authorization boundary. Default `null` = guard off, 4.25.0 behaviour.
     */
    val expectedProjectId: String? = null,
    /**
     * ADR-033 §8-Q1 — when `signInAnonymously()` / `ensureSession()` runs with
     * no session and a held guest is on the device, restore the NEWEST eligible
     * held guest instead of minting a fresh one (visible as `GuestReleased
     * (RESTORED)` then `SignedIn(cause = RESTORE)`). `false` mints while the
     * held-slot count is under the cap and still restores at the cap. A guest
     * held when the then-current account was deleted is never auto-restored
     * either way (explicit `restoreHeldGuest(id)` only).
     */
    val autoRestoreHeldGuest: Boolean = true,
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
