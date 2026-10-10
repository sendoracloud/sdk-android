package com.sendoracloud.sdk.internal

import com.sendoracloud.sdk.SendoraCloudAuthUser
import org.json.JSONArray
import org.json.JSONObject

/**
 * ADR-033 wave 1 — the records the auth machine persists, and their codecs.
 *
 * Three shapes, one owner (`commit()`):
 *  - the legacy `auth_user` blob (format FROZEN since 4.0; gains an OPTIONAL
 *    `project` key that a 4.25.0 reader ignores — ADR-023 additive),
 *  - the `auth_session` record (4.26.0): the whole slot in one value, read
 *    first on hydrate, dual-written with the four frozen keys,
 *  - a held-guest slot (`auth_held_<i>`, §3.2): ~300 B, NO access token, NO
 *    user blob — restore/claim always refresh first.
 *
 * Codecs are total on the read side: anything unreadable decodes to `null`
 * and the CALLER decides what that means (INV-9: an unreadable user blob with
 * a refresh token present is `unknown`, never `signed_out`; an unparseable
 * held slot is KEPT and ignored, never cleared — P11).
 */

/** The ONE identity slot as installed: user + trio + deadline. */
internal data class AuthRecord(
    val user: SendoraCloudAuthUser,
    val accessToken: String,
    val refreshToken: String,
    /** Unix-millis deadline tracked in the DEVICE clock frame (`now + expiresIn` at mint). */
    val expiresAt: Long,
) {
    /** The server session FAMILY id — the identity CAS key (INV-2). `null` on a pre-s58.322 token. */
    val sid: String? by lazy { decodeJwtPayload(accessToken)?.optString("sid", "")?.takeIf { it.isNotEmpty() } }

    /**
     * The JWT `project` claim as a held slot records it: the string, or `null`
     * when the claim is an explicit null OR unreadable (§3.2 `held_guests`:
     * "`null` when unreadable"). Judged again on the refresh response at
     * restore when null.
     */
    val projectClaim: String? by lazy {
        val payload = decodeJwtPayload(accessToken) ?: return@lazy null
        if (!payload.has(PROJECT_CLAIM) || payload.isNull(PROJECT_CLAIM)) null else payload.opt(PROJECT_CLAIM) as? String
    }

    /** `true` when the token names its project claim at all (string OR explicit null). */
    val projectClaimPresent: Boolean by lazy { decodeJwtPayload(accessToken)?.has(PROJECT_CLAIM) == true }

    /** Explicit-null claim = the org-wide pool (a real bucket, distinct from absent). */
    val projectClaimIsNull: Boolean by lazy { decodeJwtPayload(accessToken)?.let { it.has(PROJECT_CLAIM) && it.isNull(PROJECT_CLAIM) } == true }
}

/**
 * ONE held slot (§3.2 `held_guests`, `HeldGuest` in `packages/shared`).
 * `tokenAtHold` lets the deprecated `merge(anonRefreshToken)` route an
 * integrator-journalled token to the right slot even after a rotation.
 */
internal data class HeldGuest(
    val userId: String,
    val sid: String?,
    val refreshToken: String,
    val tokenAtHold: String,
    val heldAt: Long,
    val project: String?,
    val autoRestore: Boolean,
) {
    val v: Int get() = 1

    fun toJson(): String = JSONObject().apply {
        put("v", v)
        put("userId", userId)
        put("sid", sid ?: JSONObject.NULL)
        put("refreshToken", refreshToken)
        put("tokenAtHold", tokenAtHold)
        put("heldAt", heldAt)
        put("project", project ?: JSONObject.NULL)
        put("autoRestore", autoRestore)
    }.toString()

    companion object {
        /**
         * `null` = unreadable (a reader that sees a `v` it does not know KEEPS
         * the slot and ignores it — never clears, INV-9).
         */
        fun fromJson(raw: String): HeldGuest? = runCatching {
            val o = JSONObject(raw)
            if (o.optInt("v", -1) != 1) return null
            val userId = o.optString("userId", "")
            val refresh = o.optString("refreshToken", "")
            if (userId.isEmpty() || refresh.isEmpty()) return null
            HeldGuest(
                userId = userId,
                sid = o.optStringOrNull("sid"),
                refreshToken = refresh,
                tokenAtHold = o.optString("tokenAtHold", refresh),
                heldAt = o.optLong("heldAt", 0L),
                project = o.optStringOrNull("project"),
                autoRestore = o.optBoolean("autoRestore", true),
            )
        }.getOrNull()
    }
}

/** A physical `auth_held_<i>` value: the raw string (always kept) + its parse (may be null). */
internal class HeldSlot(val raw: String, val parsed: HeldGuest?)

/** The decoded `auth_session` record. Any field may be absent on a torn write. */
internal data class SessionRecordParts(
    val user: SendoraCloudAuthUser?,
    val accessToken: String?,
    val refreshToken: String?,
    val expiresAt: Long,
    /** Held-guest userIds whose `POST /guest/held` report has not succeeded yet (B15, non-secret). */
    val heldReportPending: List<String>,
)

internal object AuthCodecs {
    /** The legacy `auth_user` encoding — FROZEN shape + optional `project` (4.26.0). */
    fun userToJson(user: SendoraCloudAuthUser): JSONObject = JSONObject().apply {
        put("id", user.id)
        put("email", user.email ?: JSONObject.NULL)
        put("emailVerified", user.emailVerified)
        put("name", user.name ?: JSONObject.NULL)
        put("isAnonymous", user.isAnonymous)
        put("signupMethod", user.signupMethod ?: JSONObject.NULL) // s58.266
        put("lastLoginMethod", user.lastLoginMethod ?: JSONObject.NULL)
        // ADR-033 B17: the project pool. Written ONLY when known — absent and
        // null are different answers, and a 4.25.0 reader ignores the key.
        if (user.projectKnown) put("project", user.project ?: JSONObject.NULL)
    }

    /** `null` for a malformed blob or an empty id (corruption / a forged write). */
    fun userFromJson(obj: JSONObject): SendoraCloudAuthUser? {
        val id = obj.optString("id", "")
        if (id.isEmpty()) return null
        return SendoraCloudAuthUser(
            id = id,
            email = obj.optStringOrNull("email"),
            emailVerified = obj.optBoolean("emailVerified", false),
            name = obj.optStringOrNull("name"),
            isAnonymous = obj.optBoolean("isAnonymous", false),
            signupMethod = obj.optStringOrNull("signupMethod"),
            lastLoginMethod = obj.optStringOrNull("lastLoginMethod"),
            project = obj.optStringOrNull("project"),
            projectKnown = obj.has("project"),
        )
    }

    fun userFromJson(raw: String): SendoraCloudAuthUser? = runCatching { userFromJson(JSONObject(raw)) }.getOrNull()

    /** The user as a response envelope carries it (`data.user`), with B17's `project` presence preserved. */
    fun userFromMap(userMap: Map<String, Any?>): SendoraCloudAuthUser? {
        val id = userMap["id"] as? String
        if (id.isNullOrEmpty()) return null
        return SendoraCloudAuthUser(
            id = id,
            email = userMap["email"] as? String,
            emailVerified = userMap["emailVerified"] as? Boolean ?: false,
            name = userMap["name"] as? String,
            isAnonymous = userMap["isAnonymous"] as? Boolean ?: false,
            signupMethod = userMap["signupMethod"] as? String, // s58.266
            lastLoginMethod = userMap["lastLoginMethod"] as? String,
            project = userMap["project"] as? String,
            projectKnown = userMap.containsKey("project"),
        )
    }

    fun sessionToJson(record: AuthRecord, heldReportPending: List<String>): String = JSONObject().apply {
        put("v", 2)
        put("user", userToJson(record.user))
        put("accessToken", record.accessToken)
        put("refreshToken", record.refreshToken)
        put("accessExpiresAt", record.expiresAt)
        put("heldReportPending", JSONArray(heldReportPending))
    }.toString()

    /** Total: a torn record still yields whatever parts it carries (INV-9 decides what they mean). */
    fun sessionFromJson(raw: String): SessionRecordParts? = runCatching {
        val o = JSONObject(raw)
        val pending = o.optJSONArray("heldReportPending")?.let { arr -> (0 until arr.length()).mapNotNull { arr.optString(it, "").takeIf { s -> s.isNotEmpty() } } } ?: emptyList()
        SessionRecordParts(
            user = o.optJSONObject("user")?.let { userFromJson(it) },
            accessToken = o.optStringOrNull("accessToken"),
            refreshToken = o.optStringOrNull("refreshToken"),
            expiresAt = o.optLong("accessExpiresAt", 0L),
            heldReportPending = pending,
        )
    }.getOrNull()
}

/** `opt` that maps JSON null AND absence to Kotlin null, and refuses non-strings. */
internal fun JSONObject.optStringOrNull(key: String): String? =
    if (!has(key) || isNull(key)) null else opt(key) as? String
