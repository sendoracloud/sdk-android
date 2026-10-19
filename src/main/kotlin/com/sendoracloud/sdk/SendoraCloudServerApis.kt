package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.AuthTransport

/**
 * 4.29.0 — the server consent + feature-flag APIs, and the identity-token rule
 * they share (port of RN `withInputIdentityToken`, sdk-react-native 1.43.0).
 *
 * ⚠ Bodies never carry a null value: Android's built-in `org.json` writes one
 * as JSON `null` and the routes' `.optional()` fields refuse it (the 4.28 lesson).
 * Every builder below adds a key only when its value is non-null.
 */

/** identify()'s `(userId, identityToken)` pair — in memory only, never persisted; cleared by `reset()`. */
internal data class IdentityProof(val userId: String, val token: String)

/** The feature-flag routes accept an `identityToken` of at most 128 chars (`evaluateFlagSchema`). */
internal const val FLAG_IDENTITY_TOKEN_MAX = 128

/** The consent routes accept an `identityToken` of at most 256 chars (`recordConsentSchema`). */
internal const val CONSENT_IDENTITY_TOKEN_MAX = 256

/**
 * The body with an `identityToken`: an EXPLICIT one wins (sent as given);
 * otherwise identify()'s remembered token is added ONLY when [userId] — the
 * user the call is about — IS the user that token was issued for, and only if
 * it fits the route's [maxLen]. Anyone else's call goes out without one (a
 * token proves exactly one userId; attaching it to another would be refused,
 * or worse, accepted for the wrong person).
 */
internal fun withInputIdentityToken(
    body: Map<String, Any?>,
    explicit: String?,
    userId: String?,
    remembered: IdentityProof?,
    maxLen: Int,
): Map<String, Any?> {
    if (explicit != null) return body + ("identityToken" to explicit)
    if (remembered == null || userId == null || userId != remembered.userId) return body
    if (remembered.token.isEmpty() || remembered.token.length > maxLen) return body
    return body + ("identityToken" to remembered.token)
}

/** A refused / failed server call. [status] 0 = no answer (offline, timeout, not configured). */
class SendoraCloudApiException(
    val operation: String,
    val status: Int,
    val code: String,
    message: String,
) : Exception("[SendoraCloud] $operation failed: $code ($status) — $message")

/** Shared transport plumbing: a 2xx `data` or a thrown [SendoraCloudApiException] — never a silent null. */
internal suspend fun callServer(transport: AuthTransport?, operation: String, path: String, body: Map<String, Any?>): Any? {
    val client = transport ?: throw SendoraCloudApiException(operation, 0, "NOT_CONFIGURED", "SendoraCloud.init() has not run")
    val response = client.post(path, body)
        ?: throw SendoraCloudApiException(operation, 0, "NETWORK", "no response (offline, timed out or backing off)")
    if (response["success"] == true) return response["data"]
    val error = response["error"] as? Map<*, *>
    throw SendoraCloudApiException(
        operation,
        (error?.get("status") as? Number)?.toInt() ?: 0,
        error?.get("code") as? String ?: "UNKNOWN",
        error?.get("message") as? String ?: "request refused",
    )
}

private fun Map<*, *>.str(key: String): String? = this[key] as? String

// ─── consent ────────────────────────────────────────────────────────────────

/** What `POST /consent/record` stored (`consent_records` row). */
data class ConsentRecordResult(
    val id: String,
    val purpose: String,
    val granted: Boolean,
    val userId: String?,
    val email: String?,
    val source: String?,
    val createdAt: String?,
    /** True when the server could prove the record is the user's own (secret key / Bearer / identity token). */
    val sourceVerified: Boolean?,
) {
    internal companion object {
        fun decode(data: Any?): ConsentRecordResult {
            val m = data as? Map<*, *> ?: throw SendoraCloudApiException("consent.record", 200, "BAD_RESPONSE", "no data")
            return ConsentRecordResult(
                id = m.str("id") ?: throw SendoraCloudApiException("consent.record", 200, "BAD_RESPONSE", "no id"),
                purpose = m.str("purpose") ?: "",
                granted = m["granted"] as? Boolean ?: false,
                userId = m.str("userId"), email = m.str("email"), source = m.str("source"),
                createdAt = m.str("createdAt"), sourceVerified = m["sourceVerified"] as? Boolean,
            )
        }
    }
}

/** What `POST /consent/deletion-request` answered. `status` is `pending` (proven) or `unconfirmed` (an emailed link must confirm it). */
data class DeletionRequestResult(
    val id: String,
    val status: String,
    val userId: String?,
    val email: String?,
    val reason: String?,
    val createdAt: String?,
) {
    internal companion object {
        fun decode(data: Any?): DeletionRequestResult {
            val m = data as? Map<*, *> ?: throw SendoraCloudApiException("consent.requestDeletion", 200, "BAD_RESPONSE", "no data")
            return DeletionRequestResult(
                id = m.str("id") ?: throw SendoraCloudApiException("consent.requestDeletion", 200, "BAD_RESPONSE", "no id"),
                status = m.str("status") ?: "",
                userId = m.str("userId"), email = m.str("email"), reason = m.str("reason"), createdAt = m.str("createdAt"),
            )
        }
    }
}

// ─── flags ──────────────────────────────────────────────────────────────────

/**
 * One evaluated flag. [reason] = the server's `ruleMatched` (`default`,
 * `inactive`, `not_found`, `env_disabled`, a rule id…); [variant] is the
 * server's `variant` when it sends one (it does not today — null), never
 * invented from [value].
 */
data class FlagValue(val key: String, val value: Any?, val variant: String?, val reason: String) {
    internal companion object {
        fun decode(m: Map<*, *>, fallbackKey: String? = null): FlagValue? {
            val key = m.str("key") ?: fallbackKey ?: return null
            return FlagValue(key, m["value"], m.str("variant"), m.str("ruleMatched") ?: m.str("reason") ?: "")
        }
    }
}

/**
 * `SendoraCloud.flags` — server-side evaluation (`/feature-flags/evaluate`,
 * `/feature-flags/evaluate-all`). `userId` defaults to the identified user
 * (`identify()` / the signed-in account); identify()'s identity token rides
 * along only for THAT user, so audience rules can trust it (server F65).
 */
class SendoraCloudFlags internal constructor(
    private val transportProvider: () -> AuthTransport? = { SendoraCloud.supportTransport() },
    private val userIdProvider: () -> String? = { SendoraCloud.analyticsUserId() },
    private val proofProvider: () -> IdentityProof? = { SendoraCloud.identityProof() },
) {
    internal fun evaluateBody(key: String, userId: String?, entityId: String?, environment: String?, identityToken: String?): Map<String, Any?> {
        val uid = userId ?: userIdProvider()
        val body = buildMap<String, Any?> {
            put("key", key)
            uid?.let { put("userId", it) }
            entityId?.let { put("entityId", it) }
            environment?.let { put("environment", it) }
        }
        return withInputIdentityToken(body, identityToken, uid, proofProvider(), FLAG_IDENTITY_TOKEN_MAX)
    }

    internal fun evaluateAllBody(userId: String?, entityId: String?, environment: String?, identityToken: String?): Map<String, Any?> {
        val uid = userId ?: userIdProvider()
        val body = buildMap<String, Any?> {
            uid?.let { put("userId", it) }
            entityId?.let { put("entityId", it) }
            environment?.let { put("environment", it) }
        }
        return withInputIdentityToken(body, identityToken, uid, proofProvider(), FLAG_IDENTITY_TOKEN_MAX)
    }

    /** Evaluate one flag. Throws [SendoraCloudApiException] on a refusal or no answer. */
    suspend fun evaluate(
        key: String,
        userId: String? = null,
        entityId: String? = null,
        environment: String? = null,
        identityToken: String? = null,
    ): FlagValue {
        val data = callServer(transportProvider(), "flags.evaluate", "/feature-flags/evaluate", evaluateBody(key, userId, entityId, environment, identityToken))
        return (data as? Map<*, *>)?.let { FlagValue.decode(it, key) }
            ?: throw SendoraCloudApiException("flags.evaluate", 200, "BAD_RESPONSE", "no flag in the response")
    }

    /** Evaluate every flag of the key's project in one round trip, keyed by flag key. */
    suspend fun evaluateAll(
        userId: String? = null,
        entityId: String? = null,
        environment: String? = null,
        identityToken: String? = null,
    ): Map<String, FlagValue> {
        val data = callServer(transportProvider(), "flags.evaluateAll", "/feature-flags/evaluate-all", evaluateAllBody(userId, entityId, environment, identityToken))
        return when (data) {
            // The server answers an ARRAY of `{ key, value, ruleMatched }`.
            is List<*> -> data.mapNotNull { (it as? Map<*, *>)?.let { m -> FlagValue.decode(m) } }.associateBy { it.key }
            // …tolerate a key → value map too.
            is Map<*, *> -> data.entries.mapNotNull { (k, v) -> (v as? Map<*, *>)?.let { FlagValue.decode(it, k as? String) } }.associateBy { it.key }
            else -> throw SendoraCloudApiException("flags.evaluateAll", 200, "BAD_RESPONSE", "no flags in the response")
        }
    }
}
