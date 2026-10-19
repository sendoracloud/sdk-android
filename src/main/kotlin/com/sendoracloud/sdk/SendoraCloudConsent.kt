package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.AuthTransport
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Consent. Two different things live here:
 *  - the LOCAL event gate — [grant] / [revoke] / [isGranted]: events buffer on
 *    the device until `grant()` (unchanged since 4.0);
 *  - 4.29.0 — the SERVER consent ledger: [record] (`POST /consent/record`) and
 *    [requestDeletion] (`POST /consent/deletion-request`), the GDPR / CCPA
 *    evidence and right-to-erasure requests. They do not touch the local gate.
 *
 * identify()'s identity token rides along only when the call's `userId` is the
 * identified user (it proves the record is that user's own, server F64); an
 * explicit `identityToken` always wins.
 */
class SendoraCloudConsent internal constructor(
    initial: Boolean,
    private val transportProvider: () -> AuthTransport? = { SendoraCloud.supportTransport() },
    private val proofProvider: () -> IdentityProof? = { SendoraCloud.identityProof() },
) {
    private val granted = AtomicBoolean(initial)
    private val listeners = CopyOnWriteArrayList<(Boolean) -> Unit>()

    val isGranted: Boolean get() = granted.get()

    fun grant() = set(true)
    fun revoke() = set(false)

    internal fun subscribe(cb: (Boolean) -> Unit) { listeners.add(cb) }

    private fun set(value: Boolean) {
        if (!granted.compareAndSet(!value, value)) return
        for (cb in listeners) runCatching { cb(value) }
    }

    // ─── server ledger (4.29.0) ─────────────────────────────────────────────

    internal fun recordBody(
        purpose: String, granted: Boolean, entityId: String?, userId: String?, email: String?, source: String?, identityToken: String?,
    ): Map<String, Any?> {
        val body = buildMap<String, Any?> {
            put("purpose", purpose)
            put("granted", granted)
            entityId?.let { put("entityId", it) }
            userId?.let { put("userId", it) }
            email?.let { put("email", it) }
            source?.let { put("source", it) }
        }
        return withInputIdentityToken(body, identityToken, userId, proofProvider(), CONSENT_IDENTITY_TOKEN_MAX)
    }

    internal fun deletionBody(entityId: String?, userId: String?, email: String?, reason: String?, identityToken: String?): Map<String, Any?> {
        val body = buildMap<String, Any?> {
            entityId?.let { put("entityId", it) }
            userId?.let { put("userId", it) }
            email?.let { put("email", it) }
            reason?.let { put("reason", it) }
        }
        return withInputIdentityToken(body, identityToken, userId, proofProvider(), CONSENT_IDENTITY_TOKEN_MAX)
    }

    /**
     * Record a consent decision on the server. [purpose] ∈ `marketing` |
     * `analytics` | `functional` | `necessary`. Throws [SendoraCloudApiException]
     * on a refusal (status + server code) or no answer.
     */
    suspend fun record(
        purpose: String,
        granted: Boolean,
        entityId: String? = null,
        userId: String? = null,
        email: String? = null,
        source: String? = null,
        identityToken: String? = null,
    ): ConsentRecordResult = ConsentRecordResult.decode(
        callServer(transportProvider(), "consent.record", "/consent/record", recordBody(purpose, granted, entityId, userId, email, source, identityToken)),
    )

    /**
     * Ask the app's team to delete the data held about a person (GDPR art. 17).
     * Not `auth.deleteAccount()` — that deletes the signed-in account itself. A
     * request the server cannot prove comes back `unconfirmed` (an emailed link
     * must confirm it). Throws [SendoraCloudApiException] on a refusal.
     */
    suspend fun requestDeletion(
        entityId: String? = null,
        userId: String? = null,
        email: String? = null,
        reason: String? = null,
        identityToken: String? = null,
    ): DeletionRequestResult = DeletionRequestResult.decode(
        callServer(transportProvider(), "consent.requestDeletion", "/consent/deletion-request", deletionBody(entityId, userId, email, reason, identityToken)),
    )
}
