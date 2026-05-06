package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.SendoraCloudLogger
import com.sendoracloud.sdk.internal.Storage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject

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
     */
    suspend fun getAccessToken(): String? {
        val token = storage.authAccessToken ?: return null
        val exp = cachedExpiresAt
        val nowMs = System.currentTimeMillis()
        if (exp > 0 && nowMs < exp - refreshSafetyMs) return token
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
        // Wipe BEFORE the network call so any track() during the auth
        // round-trip can't attach to the prior identity (TOCTOU).
        if (cachedUser != null) wipeLocalIdentity()

        val response = client.post("/auth-service/login", mapOf("email" to email, "password" to password))
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

    /** Exchange the MFA challenge token + TOTP/recovery code for a session. */
    suspend fun challengeMfa(challengeToken: String, code: String): Result<SendoraCloudAuthUser> = mutex.withLock {
        callAuth("/auth-service/mfa/challenge", mapOf("challengeToken" to challengeToken, "code" to code))
    }

    // --- Magic link ---

    suspend fun sendMagicLink(email: String): Result<Unit> {
        val response = client.post("/auth-service/magic-link/request", mapOf("email" to email))
        return parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    suspend fun verifyMagicLink(token: String): Result<SendoraCloudAuthUser> = mutex.withLock {
        if (!storage.isSecureAvailable) {
            return@withLock Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        if (cachedUser != null) wipeLocalIdentity()
        callAuth("/auth-service/magic-link/verify", mapOf("token" to token))
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
        if (cachedUser != null) wipeLocalIdentity()
        callAuth("/auth-service/email-otp/verify", mapOf("email" to email, "code" to code))
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

    private suspend fun refreshAccessToken(): String? = refreshMutex.withLock {
        val nowMs = System.currentTimeMillis()
        // Re-check after acquiring the lock; another caller may have
        // already refreshed.
        val exp = cachedExpiresAt
        val cached = storage.authAccessToken
        if (cached != null && exp > 0 && nowMs < exp - refreshSafetyMs) return@withLock cached

        val refresh = storage.authRefreshToken ?: return@withLock null
        val response = client.post("/auth-service/token/refresh", mapOf("refreshToken" to refresh))
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
    }

    private suspend fun wipeLocalIdentity() {
        cachedUser = null
        cachedExpiresAt = 0L
        storage.clearAuthTokens()
        onAnonymousWipe()
    }
}
