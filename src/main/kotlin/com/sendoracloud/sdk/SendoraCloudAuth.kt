package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.SendoraCloudLogger
import com.sendoracloud.sdk.internal.Storage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import kotlin.random.Random

/**
 * Auth Service surface for the Android SDK.
 *
 * Three flows mirroring the web + iOS + RN SDKs:
 *   - signInAnonymously()        — POST /auth-service/anonymous
 *   - signUp(email, password)    — upgrades the same row in place
 *                                  when called from an anonymous
 *                                  session; otherwise creates a
 *                                  fresh account.
 *   - signIn(email, password)    — logs into an existing account.
 *                                  Local identity is wiped FIRST so
 *                                  any track() during the round-trip
 *                                  can't attach to the prior identity.
 *   - signOut()                  — wipe FIRST, fire-and-forget revoke.
 *                                  User is logged out on device even
 *                                  if the network call hangs.
 *
 * All public ops are serialized through a single Mutex so a UI
 * double-submit can't mint two anonymous users or interleave a
 * signIn + signOut. Response payloads are validated non-empty
 * before persisting — a malformed/MitM'd response can't install an
 * `id = ""` user.
 *
 * Tokens persist in `EncryptedSharedPreferences` only. If secure
 * storage is unavailable, persistence FAILS instead of falling back
 * to plaintext SharedPreferences.
 */

data class SendoraCloudAuthUser(
    val id: String,
    val email: String?,
    val emailVerified: Boolean,
    val name: String?,
    val isAnonymous: Boolean,
)

sealed class SendoraCloudAuthError(message: String) : Throwable(message) {
    class EmailAlreadyTaken(message: String) : SendoraCloudAuthError(message)
    class Unauthorized(message: String) : SendoraCloudAuthError(message)
    class Network(message: String) : SendoraCloudAuthError(message)
    class SecureStorageUnavailable(message: String) : SendoraCloudAuthError(message)
    class Unknown(message: String) : SendoraCloudAuthError(message)
}

/**
 * Detail handed to onDeviceTakeover subscribers. Fires once per
 * identified-signin call where the backend retired an anonymous
 * user_id (anon → identified flip on the same device, s58.111+).
 * Host app's only job is to delete the matching row from any
 * local mirror table so audience queries joining on user_id stop
 * matching the stale anon row.
 */
data class DeviceTakeoverEvent(
    val retiredAnonUserId: String,
    val identifiedUserId: String,
    val at: Long,
)

class SendoraCloudAuth internal constructor(
    private val client: ApiClient,
    private val storage: Storage,
    private val onIdentityChange: (String?) -> Unit,
    private val onAnonymousWipe: suspend () -> Unit,
) {
    @Volatile private var cachedUser: SendoraCloudAuthUser? = null
    @Volatile private var cachedExpiresAt: Long = 0L
    private val mutex = Mutex()
    private val refreshMutex = Mutex()
    // s58.116 — inline device-takeover listeners. UUID-keyed so
    // callers can unsubscribe via the returned lambda.
    private val takeoverListeners = java.util.concurrent.ConcurrentHashMap<java.util.UUID, (DeviceTakeoverEvent) -> Unit>()
    @Volatile private var lastTakeover: DeviceTakeoverEvent? = null
    // Long-lived coroutine scope for the proactive-refresh cron (s58.73).
    // SupervisorJob so a single tick failure doesn't kill the loop.
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val refreshSafetyMs = 30_000L

    init {
        // Re-hydrate session from EncryptedSharedPreferences. Drop the
        // cache if the JSON is malformed or carries an empty id —
        // either signal corruption / a forged write.
        storage.authUserJson?.let { json ->
            runCatching {
                val obj = JSONObject(json)
                val id = obj.optString("id")
                if (id.isNotEmpty()) {
                    cachedUser = SendoraCloudAuthUser(
                        id = id,
                        email = obj.opt("email")?.takeIf { it != JSONObject.NULL } as? String,
                        emailVerified = obj.optBoolean("emailVerified", false),
                        name = obj.opt("name")?.takeIf { it != JSONObject.NULL } as? String,
                        isAnonymous = obj.optBoolean("isAnonymous", false),
                    )
                    cachedExpiresAt = storage.authAccessExpiresAt
                    cachedUser?.let { onIdentityChange(it.id) }
                } else {
                    storage.clearAuthTokens()
                }
            }.onFailure { storage.clearAuthTokens() }
        }
    }

    val currentUser: SendoraCloudAuthUser? get() = cachedUser

    /** Synchronous read — returns whatever's cached, even if expired.
     *  Prefer `getAccessToken()` for transparent refresh. */
    val accessToken: String? get() = storage.authAccessToken

    /**
     * Returns a non-expired access token. Triggers a single-flight
     * refresh if the cached token is past expiry.
     *
     * s58.47 — when the cached ACCESS token is missing but a refresh
     * token is still in EncryptedSharedPreferences (cold start after
     * the access token's 15-min TTL elapsed, partial persist, or
     * AndroidKeyStore eviction), drive a refresh instead of
     * returning null. Pre-s58.47 we bailed immediately, which left
     * the host app reading null and triggering a fresh anonymous
     * mint on every cold launch.
     */
    suspend fun getAccessToken(): String? {
        val token = storage.authAccessToken
        val exp = cachedExpiresAt
        val nowMs = System.currentTimeMillis()
        if (token != null && exp > 0 && nowMs < exp - refreshSafetyMs) return token
        // Either no access token at all, or it's past (expiry - safety).
        // refreshAccessToken handles both: it short-circuits when no
        // refresh token is in storage either, returning null.
        return refreshAccessToken()
    }

    suspend fun signInAnonymously(
        name: String? = null,
        metadata: Map<String, Any>? = null,
    ): Result<SendoraCloudAuthUser> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable(
                "EncryptedSharedPreferences unavailable — refusing to mint a session that can't be persisted securely"
            ))
        }
        val body = mutableMapOf<String, Any?>()
        name?.let { body["name"] = it }
        metadata?.let { body["metadata"] = it }
        callAuth("/auth-service/anonymous", body)
    }

    suspend fun signUp(
        email: String,
        password: String,
        name: String? = null,
        metadata: Map<String, Any>? = null,
    ): Result<SendoraCloudAuthUser> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable(
                "EncryptedSharedPreferences unavailable — refusing to persist auth tokens"
            ))
        }
        val isAnonymous = cachedUser?.isAnonymous == true
        val refresh = storage.authRefreshToken
        if (isAnonymous && refresh != null) {
            val body = mutableMapOf<String, Any?>(
                "refreshToken" to refresh,
                "email" to email,
                "password" to password,
            )
            name?.let { body["name"] = it }
            return@withLock callAuth("/auth-service/upgrade", body)
        }
        // Non-anonymous identified state — wipe BEFORE the network call
        // so any track() during the auth round-trip can't attach to
        // the prior identity.
        if (cachedUser != null && cachedUser?.isAnonymous == false) {
            wipeLocalIdentity()
        }
        val body = mutableMapOf<String, Any?>("email" to email, "password" to password)
        name?.let { body["name"] = it }
        metadata?.let { body["metadata"] = it }
        callAuth("/auth-service/signup", body)
    }

    suspend fun signIn(email: String, password: String): Result<SendoraCloudAuthUser> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable(
                "EncryptedSharedPreferences unavailable — refusing to persist auth tokens"
            ))
        }
        // Device-takeover (backend s58.111): if this device holds an
        // anonymous session, forward its refresh token to /login so
        // the backend revokes the anon session, reassigns this
        // device's push tokens to the identified user, and deletes
        // the anon user row. One device → one user_id on the platform
        // side. Read BEFORE wipe.
        val prevAnonRefreshToken: String? = if (cachedUser?.isAnonymous == true) storage.authRefreshToken else null

        // Wipe BEFORE the network call so any track() during the auth
        // round-trip can't attach to the prior identity (TOCTOU).
        if (cachedUser != null) wipeLocalIdentity()

        val body = mutableMapOf<String, Any?>("email" to email, "password" to password)
        if (prevAnonRefreshToken != null) body["prevAnonRefreshToken"] = prevAnonRefreshToken
        val response = client.post("/auth-service/login", body)
        val err = parseError(response)
        if (err != null) return@withLock Result.failure(err)
        val parsed = parseSuccess(response)
            ?: return@withLock Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        persist(response!!)
        Result.success(parsed.first)
    }

    /**
     * Login outcome — `Authenticated` for the standard path,
     * `MfaRequired` when the account has MFA enabled. Caller follows
     * up with `challengeMfa()` to mint the actual session.
     */
    sealed class SignInOutcome {
        data class Authenticated(val user: SendoraCloudAuthUser) : SignInOutcome()
        data class MfaRequired(val challengeToken: String, val userId: String) : SignInOutcome()
    }

    /**
     * Like `signIn()` but discriminates the MFA-required path. Use this
     * when supporting MFA on end-users.
     */
    suspend fun signInWithMfaSupport(email: String, password: String): Result<SignInOutcome> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        if (cachedUser != null) wipeLocalIdentity()
        val response = client.post("/auth-service/login", mapOf("email" to email, "password" to password))
        val err = parseError(response)
        if (err != null) return@withLock Result.failure(err)
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?>
            ?: return@withLock Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        if (data["mfaRequired"] == true) {
            val challengeToken = data["mfaChallengeToken"] as? String
                ?: return@withLock Result.failure(SendoraCloudAuthError.Unknown("Missing mfaChallengeToken"))
            @Suppress("UNCHECKED_CAST")
            val userMap = data["user"] as? Map<String, Any?>
            val userId = (userMap?.get("id") as? String) ?: ""
            return@withLock Result.success(SignInOutcome.MfaRequired(challengeToken, userId))
        }
        val parsed = parseSuccess(response)
            ?: return@withLock Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        persist(response!!)
        Result.success(SignInOutcome.Authenticated(parsed.first))
    }

    /**
     * Returns the stored anon refresh token iff the local subject is
     * currently anonymous. Used by every identified-session-mint path
     * so the backend can run device-takeover (s58.111 + s58.112).
     * `internal` so cross-file helpers (passkey assertion) can read
     * it without copying the gating logic.
     */
    internal fun takeoverHint(): String? =
        if (cachedUser?.isAnonymous == true) storage.authRefreshToken else null

    // --- Device-takeover listener (s58.116 parity with RN 1.0.5) ---

    /**
     * Register a callback fired when the backend retires an anon
     * `user_id` during a signin on this device. Use it to delete
     * the matching row from any local mirror table — Sendora's own
     * `auth_service_users` + `push_tokens` are already cleaned up
     * server-side. Returns an unsubscribe lambda.
     *
     * Listeners fire on every identified-signin path: signIn /
     * loginSocial / verifyMagicLink / verifyEmailOtp /
     * challengeMfa / passkey authenticate. Local-only — survives
     * webhook receiver downtime. For server-pipeline cleanup also
     * subscribe to the `auth.device_takeover` webhook.
     */
    fun onDeviceTakeover(listener: (DeviceTakeoverEvent) -> Unit): () -> Unit {
        val key = java.util.UUID.randomUUID()
        takeoverListeners[key] = listener
        return { takeoverListeners.remove(key) }
    }

    /**
     * Returns the most recent takeover the SDK observed in this
     * session, or null if none. Lets late subscribers pick up the
     * takeover their handler missed.
     */
    fun getLastDeviceTakeover(): DeviceTakeoverEvent? = lastTakeover

    /**
     * Internal — called from every identified-signin path with the
     * `retiredAnonUserId` parsed off the backend response. Snapshot
     * + dispatch outside any mutex so a listener can't deadlock by
     * re-entering the auth surface.
     *
     * Validates UUID shape before firing. The value comes from a
     * response body that a MitM could tamper; a non-UUID value
     * handed to a listener that interpolates it into a path (the
     * documented pattern) becomes a path-injection sink in the host
     * app.
     */
    internal fun fireDeviceTakeover(retiredAnonUserId: String, identifiedUserId: String) {
        if (retiredAnonUserId.isEmpty()) return
        if (!isCanonicalUuid(retiredAnonUserId)) return
        val evt = DeviceTakeoverEvent(
            retiredAnonUserId = retiredAnonUserId,
            identifiedUserId = identifiedUserId,
            at = System.currentTimeMillis(),
        )
        lastTakeover = evt
        for (fn in takeoverListeners.values.toList()) {
            runCatching { fn(evt) }
        }
    }

    /** Exchange the MFA challenge token + TOTP/recovery code for a session. */
    suspend fun challengeMfa(challengeToken: String, code: String): Result<SendoraCloudAuthUser> = mutex.withLock {
        val body = mutableMapOf<String, Any>("challengeToken" to challengeToken, "code" to code)
        takeoverHint()?.let { body["prevAnonRefreshToken"] = it }
        callAuth("/auth-service/mfa/challenge", body)
    }

    // --- Magic link ---

    suspend fun sendMagicLink(email: String): Result<Unit> {
        val response = client.post("/auth-service/magic-link/request", mapOf("email" to email))
        return parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    // --- Social sign-in (8 providers) ---

    /**
     * Verify an IdP-issued credential and mint a Sendora session.
     * Customer's app handles the IdP dance — typically via
     * androidx.credentials Credential Manager (Google) or the
     * provider's SDK (Facebook, etc) or a Custom Tabs flow — then
     * hands the result here.
     *
     * Provider is one of: google, github, apple, microsoft,
     * linkedin, facebook, twitter, discord. Twitter is rejected
     * server-side per OAuth 2.0 verified-email gap.
     *
     * Pass either `code` + `redirectUri` (authorization-code flow)
     * OR `idToken` (Apple-native style; rare on Android).
     */
    suspend fun loginSocial(
        provider: String,
        code: String? = null,
        idToken: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
        appleFirstName: String? = null,
        appleLastName: String? = null,
        // ADR-025 link-in-place opt-in. When anonymous + `link = true`, an
        // anon→social upgrade KEEPS the same user id (sub) — promoted in place
        // (like Firebase linkWithCredential) instead of a device-takeover that
        // mints a new id. No effect off-anon or on a collision.
        link: Boolean = false,
    ): Result<SendoraCloudAuthUser> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        // Device-takeover hint — same posture as signIn().
        val prevAnonRefreshToken: String? = if (cachedUser?.isAnonymous == true) storage.authRefreshToken else null

        if (cachedUser != null) wipeLocalIdentity()

        val body = buildMap<String, Any> {
            put("provider", provider)
            code?.let { put("code", it) }
            idToken?.let { put("idToken", it) }
            redirectUri?.let { put("redirectUri", it) }
            codeVerifier?.let { put("codeVerifier", it) }
            if (appleFirstName != null || appleLastName != null) {
                put("appleName", buildMap<String, String> {
                    appleFirstName?.let { put("firstName", it) }
                    appleLastName?.let { put("lastName", it) }
                })
            }
            prevAnonRefreshToken?.let { put("prevAnonRefreshToken", it) }
            // ADR-025: opt into link-in-place (backend ignores it unless anon + new identity).
            if (link) put("linkAnonymous", true)
        }
        callAuth("/auth-service/login/social", body)
    }

    suspend fun signInWithGoogle(code: String, redirectUri: String, link: Boolean = false) =
        loginSocial(provider = "google", code = code, redirectUri = redirectUri, link = link)

    /**
     * Google Play Games sign-in (email-less, player-keyed). Pass the
     * serverAuthCode from
     * `PlayGames.getGamesSignInClient(activity).requestServerSideAccess(webClientId, false)`
     * — obtain it via the Play Games SDK (or the Sendora helper). `link = true`
     * KEEPS the same user id when upgrading an anonymous device (ADR-025
     * link-in-place); no effect off-anon or on a collision.
     */
    suspend fun signInWithPlayGames(serverAuthCode: String, link: Boolean = false): Result<SendoraCloudAuthUser> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        // Device-takeover hint — same posture as loginSocial().
        val prevAnonRefreshToken: String? = if (cachedUser?.isAnonymous == true) storage.authRefreshToken else null

        if (cachedUser != null) wipeLocalIdentity()

        val body = buildMap<String, Any> {
            put("serverAuthCode", serverAuthCode)
            prevAnonRefreshToken?.let { put("prevAnonRefreshToken", it) }
            // ADR-025: opt into link-in-place (backend ignores it unless anon + new identity).
            if (link) put("linkAnonymous", true)
        }
        callAuth("/auth-service/login/play-games", body)
    }

    suspend fun signInWithGitHub(code: String, redirectUri: String) =
        loginSocial(provider = "github", code = code, redirectUri = redirectUri)

    /** Apple Sign In. Pass `idToken` from the native flow + name fields on first sign-in. `link` = ADR-025 keep-the-sub on an anon upgrade. */
    suspend fun signInWithApple(
        idToken: String,
        firstName: String? = null,
        lastName: String? = null,
        link: Boolean = false,
    ) = loginSocial(
        provider = "apple",
        idToken = idToken,
        appleFirstName = firstName,
        appleLastName = lastName,
        link = link,
    )

    suspend fun signInWithMicrosoft(code: String, redirectUri: String) =
        loginSocial(provider = "microsoft", code = code, redirectUri = redirectUri)

    suspend fun signInWithLinkedIn(code: String, redirectUri: String) =
        loginSocial(provider = "linkedin", code = code, redirectUri = redirectUri)

    suspend fun signInWithFacebook(code: String, redirectUri: String) =
        loginSocial(provider = "facebook", code = code, redirectUri = redirectUri)

    suspend fun signInWithDiscord(code: String, redirectUri: String) =
        loginSocial(provider = "discord", code = code, redirectUri = redirectUri)

    suspend fun verifyMagicLink(token: String): Result<SendoraCloudAuthUser> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        val prev = takeoverHint()
        if (cachedUser != null) wipeLocalIdentity()
        val body = mutableMapOf<String, Any>("token" to token)
        prev?.let { body["prevAnonRefreshToken"] = it }
        callAuth("/auth-service/magic-link/verify", body)
    }

    // --- Email OTP (6-digit cross-device code) ---

    suspend fun sendEmailOtp(email: String): Result<Unit> {
        val response = client.post("/auth-service/email-otp/request", mapOf("email" to email))
        return parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    suspend fun verifyEmailOtp(email: String, code: String): Result<SendoraCloudAuthUser> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        val prev = takeoverHint()
        if (cachedUser != null) wipeLocalIdentity()
        val body = mutableMapOf<String, Any>("email" to email, "code" to code)
        prev?.let { body["prevAnonRefreshToken"] = it }
        callAuth("/auth-service/email-otp/verify", body)
    }

    // --- Password reset + email verification ---

    /** Trigger a password-reset email. Backend always succeeds even when address is unknown (anti-enumeration). */
    suspend fun requestPasswordReset(email: String): Result<Unit> {
        val response = client.post("/auth-service/password/forgot", mapOf("email" to email))
        return parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    /** Pair the reset-email token with the user's new password. */
    suspend fun resetPassword(token: String, newPassword: String): Result<Unit> {
        val response = client.post(
            "/auth-service/password/reset",
            mapOf("token" to token, "newPassword" to newPassword),
        )
        return parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    /** Verify the email-address token from the link Sendora sent on signup. */
    suspend fun verifyEmail(token: String): Result<Unit> {
        val response = client.post("/auth-service/email/verify", mapOf("token" to token))
        return parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    /** Re-send the email-verification email for the currently-signed-in user. No-op when already verified. */
    suspend fun sendVerificationEmail(): Result<Unit> {
        val headers = bearerHeaders() ?: return Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/email/verify/resend", emptyMap(), headers)
        return parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    // --- MFA enrollment management (Bearer-authenticated) ---

    data class MfaEnrollment(val secret: String, val otpauthUrl: String, val recoveryCodes: List<String>)

    suspend fun enrollMfa(): Result<MfaEnrollment> {
        val headers = bearerHeaders() ?: return Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/mfa/enroll/start", emptyMap(), headers)
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?>
            ?: return Result.failure(SendoraCloudAuthError.Unknown("Malformed enrollment response"))
        val secret = data["secret"] as? String
        val url = data["otpauthUrl"] as? String
        @Suppress("UNCHECKED_CAST")
        val codes = (data["recoveryCodes"] as? List<String>) ?: emptyList()
        if (secret.isNullOrEmpty() || url.isNullOrEmpty()) {
            return Result.failure(SendoraCloudAuthError.Unknown("Malformed enrollment response"))
        }
        return Result.success(MfaEnrollment(secret, url, codes))
    }

    suspend fun confirmMfa(code: String): Result<Boolean> {
        val headers = bearerHeaders() ?: return Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/mfa/enroll/confirm", mapOf("code" to code), headers)
        @Suppress("UNCHECKED_CAST")
        val confirmed = (response?.get("data") as? Map<String, Any?>)?.get("confirmed") as? Boolean ?: false
        return Result.success(confirmed)
    }

    suspend fun disableMfa(): Result<Unit> {
        val headers = bearerHeaders() ?: return Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        client.post("/auth-service/mfa/disable", emptyMap(), headers)
        return Result.success(Unit)
    }

    // --- Device sessions self-service ---

    data class DeviceSession(
        val id: String,
        val deviceInfo: String?,
        val lastUsedAt: String?,
        val createdAt: String,
    )

    suspend fun listMySessions(): List<DeviceSession> {
        val headers = bearerHeaders() ?: return emptyList()
        val response = client.get("/auth-service/sessions/me", headers)
        @Suppress("UNCHECKED_CAST")
        val arr = response?.get("data") as? List<Map<String, Any?>> ?: return emptyList()
        return arr.mapNotNull { row ->
            val id = row["id"] as? String ?: return@mapNotNull null
            val createdAt = row["createdAt"] as? String ?: return@mapNotNull null
            DeviceSession(
                id = id,
                deviceInfo = row["deviceInfo"] as? String,
                lastUsedAt = row["lastUsedAt"] as? String,
                createdAt = createdAt,
            )
        }
    }

    suspend fun revokeSession(sessionId: String) {
        val headers = bearerHeaders() ?: return
        client.delete("/auth-service/sessions/me/$sessionId", headers)
    }

    suspend fun revokeAllSessions() {
        val headers = bearerHeaders() ?: return
        client.delete("/auth-service/sessions/me", headers)
    }

    /**
     * Outcome of [deleteAccount]. [status] is `"purged"` (hard-deleted now,
     * grace = 0) or `"pending"` (deactivated + sessions revoked now, hard
     * delete scheduled at [scheduledPurgeAt]; cancellable by signing back in).
     */
    data class AccountDeletionResult(
        val status: String,
        val scheduledPurgeAt: String?,
        val graceDays: Int,
    )

    /**
     * Delete the signed-in user's account (Apple App Store Guideline 5.1.1(v)).
     * Honors the project's configured grace period; wipes local identity on
     * success (the server has revoked the session). Fails when no user is
     * signed in or the request errors.
     *
     * Resolves a FRESH access token via [getAccessToken] first (refreshing a
     * past-expiry cached token) — this is a one-shot destructive action, so a
     * 401 from a stale token would silently strand the user with an undeleted
     * account (the cause of the prod 401s when "delete" was tapped after the
     * app sat idle). [getAccessToken] uses a separate `refreshMutex`, so calling
     * it while holding `mutex` here does not deadlock.
     */
    suspend fun deleteAccount(): Result<AccountDeletionResult> = mutex.withLock {
        val token = getAccessToken()
            ?: return@withLock Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val headers = mapOf("Authorization" to "Bearer $token")
        val res = client.delete("/auth-service/me", headers)
            ?: return@withLock Result.failure(SendoraCloudAuthError.Network("deleteAccount failed (network error)"))
        @Suppress("UNCHECKED_CAST")
        val data = res["data"] as? Map<String, Any?>
        if (data == null && res["error"] != null) {
            @Suppress("UNCHECKED_CAST")
            val msg = (res["error"] as? Map<String, Any?>)?.get("message") as? String ?: "deleteAccount failed"
            return@withLock Result.failure(SendoraCloudAuthError.Network(msg))
        }
        // Account is gone / deactivated server-side — drop local identity.
        wipeLocalIdentity()
        Result.success(AccountDeletionResult(
            status = data?.get("status") as? String ?: "pending",
            scheduledPurgeAt = data?.get("scheduledPurgeAt") as? String,
            graceDays = (data?.get("graceDays") as? Number)?.toInt() ?: 0,
        ))
    }

    private fun bearerHeaders(): Map<String, String>? {
        val token = storage.authAccessToken ?: return null
        return mapOf("Authorization" to "Bearer $token")
    }

    suspend fun signOut() = mutex.withLock {
        // Wipe FIRST so the user is logged out on device even if the
        // revoke request hangs (airplane mode, 5xx, circuit open).
        // Refresh token still expires server-side.
        val refresh = storage.authRefreshToken
        wipeLocalIdentity()
        if (refresh != null) {
            // Fire-and-forget on a detached scope so the local wipe
            // is the user-visible outcome.
            CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
                runCatching {
                    client.post("/auth-service/token/revoke", mapOf("refreshToken" to refresh))
                }
            }
        }
    }

    // --- Internals ---

    private suspend fun callAuth(
        path: String,
        body: Map<String, Any?>,
    ): Result<SendoraCloudAuthUser> {
        val response = client.post(path, body)
        val err = parseError(response)
        if (err != null) return Result.failure(err)
        val parsed = parseSuccess(response)
            ?: return Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        persist(response!!)
        return Result.success(parsed.first)
    }

    /**
     * Hot-path token refresh. Mutexed so a coroutine fan-out doesn't
     * produce duplicate /refresh round-trips.
     *
     * s58.46 — on a dead-token signal (INVALID_REFRESH_TOKEN /
     * UNAUTHORIZED / HTTP_401 / RATE_LIMIT) we WIPE the stored
     * refresh token. Pre-s58.46 we returned null but kept the dead
     * token in storage, so the next caller re-tried the same token
     * forever (Pulse News iOS hit /refresh ~1×/s for hours). The
     * wipe forces the next op to fall through to anonymous mint or
     * surface signed-out state to the host app instead of looping.
     */
    private suspend fun refreshAccessToken(): String? = refreshMutex.withLock {
        val nowMs = System.currentTimeMillis()
        // Re-check after acquiring the lock; another caller may have
        // already refreshed.
        val exp = cachedExpiresAt
        val cached = storage.authAccessToken
        if (cached != null && exp > 0 && nowMs < exp - refreshSafetyMs) return@withLock cached

        val refresh = storage.authRefreshToken ?: return@withLock null
        val response = client.post("/auth-service/token/refresh", mapOf("refreshToken" to refresh))
        if (response != null && response["success"] == false) {
            @Suppress("UNCHECKED_CAST")
            val error = response["error"] as? Map<String, Any?>
            val code = error?.get("code") as? String
            if (code != null && isDeadRefreshError(code)) {
                wipeLocalIdentity()
            }
            return@withLock null
        }
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?> ?: return@withLock null
        val accessToken = data["accessToken"] as? String
        val refreshToken = data["refreshToken"] as? String
        val expiresIn = (data["expiresIn"] as? Number)?.toLong()
        if (accessToken.isNullOrEmpty() || refreshToken.isNullOrEmpty() || expiresIn == null || expiresIn <= 0) {
            return@withLock null
        }
        val newExp = nowMs + expiresIn * 1000L
        storage.authAccessToken = accessToken
        storage.authRefreshToken = refreshToken
        storage.authAccessExpiresAt = newExp
        cachedExpiresAt = newExp
        accessToken
    }

    /**
     * Canonical UUID validator. Defends against tampered
     * `retiredAnonUserId` response values reaching host-app
     * listeners as a path-injection sink.
     */
    private fun isCanonicalUuid(s: String): Boolean {
        return try {
            java.util.UUID.fromString(s).toString().equals(s, ignoreCase = true)
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun isDeadRefreshError(code: String): Boolean {
        return code == "INVALID_REFRESH_TOKEN" ||
                code == "UNAUTHORIZED" ||
                code == "HTTP_401" ||
                code == "RATE_LIMIT_EXCEEDED" ||
                code == "RATE_LIMIT"
    }

    private fun parseError(response: Map<String, Any?>?): SendoraCloudAuthError? {
        if (response == null) return SendoraCloudAuthError.Network("Network request failed")
        val success = response["success"] as? Boolean ?: false
        if (success) return null
        @Suppress("UNCHECKED_CAST")
        val error = response["error"] as? Map<String, Any?>
        val code = error?.get("code") as? String ?: ""
        val message = error?.get("message") as? String ?: "Auth request failed"
        return when (code) {
            "CONFLICT", "EMAIL_ALREADY_TAKEN" -> SendoraCloudAuthError.EmailAlreadyTaken(message)
            "UNAUTHORIZED" -> SendoraCloudAuthError.Unauthorized(message)
            else -> SendoraCloudAuthError.Unknown("$code: $message")
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseSuccess(response: Map<String, Any?>?): Pair<SendoraCloudAuthUser, Map<String, Any?>>? {
        val data = response?.get("data") as? Map<String, Any?> ?: return null
        val userMap = data["user"] as? Map<String, Any?> ?: return null
        val tokensMap = data["tokens"] as? Map<String, Any?> ?: return null
        val id = userMap["id"] as? String
        if (id.isNullOrEmpty()) return null
        val accessToken = tokensMap["accessToken"] as? String
        val refreshToken = tokensMap["refreshToken"] as? String
        val expiresIn = (tokensMap["expiresIn"] as? Number)?.toLong() ?: 0L
        if (accessToken.isNullOrEmpty() || refreshToken.isNullOrEmpty() || expiresIn <= 0) return null
        val user = SendoraCloudAuthUser(
            id = id,
            email = userMap["email"] as? String,
            emailVerified = userMap["emailVerified"] as? Boolean ?: false,
            name = userMap["name"] as? String,
            isAnonymous = userMap["isAnonymous"] as? Boolean ?: false,
        )
        return user to tokensMap
    }

    internal val passkeys: SendoraCloudPasskeys by lazy {
        SendoraCloudPasskeys(
            client = client,
            storage = storage,
            installSession = { payload ->
                mutex.withLock {
                    if (!storage.isSecureAvailable) null
                    else { persist(mapOf("data" to payload)); cachedUser }
                }
            },
            wipe = { wipeLocalIdentity() },
            takeoverHintProvider = { takeoverHint() },
        )
    }

    private fun persist(response: Map<String, Any?>) {
        val (user, tokens) = parseSuccess(response) ?: return
        val accessToken = tokens["accessToken"] as String
        val refreshToken = tokens["refreshToken"] as String
        val expiresIn = (tokens["expiresIn"] as Number).toLong()
        val expMs = System.currentTimeMillis() + expiresIn * 1000L

        cachedUser = user
        cachedExpiresAt = expMs
        storage.authAccessToken = accessToken
        storage.authRefreshToken = refreshToken
        storage.authAccessExpiresAt = expMs
        val userJson = JSONObject().apply {
            put("id", user.id)
            put("email", user.email ?: JSONObject.NULL)
            put("emailVerified", user.emailVerified)
            put("name", user.name ?: JSONObject.NULL)
            put("isAnonymous", user.isAnonymous)
        }.toString()
        storage.authUserJson = userJson
        onIdentityChange(user.id)
        startProactiveRefreshCron()

        // s58.116 — fire inline device-takeover listener when the
        // backend retired an anon row during this signin. Read from
        // the outer `data` envelope; passkey path passes `data` only
        // (mapOf("data" to payload)) so this still finds it.
        @Suppress("UNCHECKED_CAST")
        val data = response["data"] as? Map<String, Any?>
        val retiredAnonUserId = data?.get("retiredAnonUserId") as? String
        if (!retiredAnonUserId.isNullOrEmpty()) {
            fireDeviceTakeover(retiredAnonUserId, user.id)
        }
    }

    private suspend fun wipeLocalIdentity() {
        cachedUser = null
        cachedExpiresAt = 0L
        storage.clearAuthTokens()
        stopProactiveRefreshCron()
        onAnonymousWipe()
    }

    // ---- Proactive refresh (s58.73) -----------------------------------
    //
    // Background coroutine that ticks every 60s + once on app foreground.
    // Refreshes when access-token TTL has burned ~80% (with ±30s jitter
    // to avoid herd synchronisation across multiple app instances on the
    // same network). Refresh becomes a scheduled event; no more 401-driven
    // race on the next interaction.
    //
    // Foreground signal: ProcessLifecycleOwner.ON_START. We import lazily
    // via reflection because androidx.lifecycle is a host-app dep on the
    // SDK side (no hard dep, lets app authors who don't want lifecycle
    // continue compiling). When unavailable we still get the 60s tick.

    private var proactiveJob: Job? = null
    private var lifecycleObserver: Any? = null

    private fun startProactiveRefreshCron() {
        if (proactiveJob?.isActive == true) return
        proactiveJob = scope.launch {
            while (isActive) {
                tickProactive()
                delay(60_000L)
            }
        }
        registerLifecycleObserver()
    }

    private fun stopProactiveRefreshCron() {
        proactiveJob?.cancel()
        proactiveJob = null
        unregisterLifecycleObserver()
    }

    private suspend fun tickProactive() {
        val nowMs = System.currentTimeMillis()
        val expMs = storage.authAccessExpiresAt
        if (expMs <= 0L) return
        val remainingMs = expMs - nowMs
        if (remainingMs <= 0L) return
        val guessOriginalMs = maxOf(remainingMs, 5L * 60_000L)
        val jitter = Random.nextLong(-30_000L, 30_000L)
        val fireWhenRemainingMs = (guessOriginalMs * 0.2).toLong() + jitter
        if (remainingMs <= fireWhenRemainingMs) {
            refreshAccessToken()
        }
    }

    private fun registerLifecycleObserver() {
        try {
            // Reflection-loaded so the SDK doesn't hard-require
            // androidx.lifecycle. Available on every modern Android app
            // that uses Jetpack, but absent in minimal setups.
            val ownerClass = Class.forName("androidx.lifecycle.ProcessLifecycleOwner")
            val owner = ownerClass.getMethod("get").invoke(null)
            val lifecycle = owner.javaClass.getMethod("getLifecycle").invoke(owner)
            val observerClass = Class.forName("androidx.lifecycle.DefaultLifecycleObserver")
            val handler = java.lang.reflect.Proxy.newProxyInstance(
                observerClass.classLoader,
                arrayOf(observerClass),
            ) { _, method, _ ->
                if (method.name == "onStart") {
                    scope.launch { tickProactive() }
                }
                null
            }
            lifecycle.javaClass.getMethod("addObserver", Class.forName("androidx.lifecycle.LifecycleObserver"))
                .invoke(lifecycle, handler)
            lifecycleObserver = handler
        } catch (_: Throwable) {
            // androidx.lifecycle missing — fall back to the 60s tick only.
        }
    }

    private fun unregisterLifecycleObserver() {
        try {
            val obs = lifecycleObserver ?: return
            val ownerClass = Class.forName("androidx.lifecycle.ProcessLifecycleOwner")
            val owner = ownerClass.getMethod("get").invoke(null)
            val lifecycle = owner.javaClass.getMethod("getLifecycle").invoke(owner)
            lifecycle.javaClass.getMethod("removeObserver", Class.forName("androidx.lifecycle.LifecycleObserver"))
                .invoke(lifecycle, obs)
        } catch (_: Throwable) {
            // No-op — observer was never registered.
        } finally {
            lifecycleObserver = null
        }
    }
}
