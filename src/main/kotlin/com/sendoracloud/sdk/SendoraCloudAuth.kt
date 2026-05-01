package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.SendoraCloudLogger
import com.sendoracloud.sdk.internal.Storage
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
 *                                  If the SDK was anonymous, local
 *                                  identity is wiped first.
 *   - signOut()                  — best-effort revoke + wipe.
 *
 * Tokens persist in EncryptedSharedPreferences via Storage. On
 * SDK init the session is re-hydrated so a cold launch keeps the
 * active user.
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
    class Unknown(message: String) : SendoraCloudAuthError(message)
}

class SendoraCloudAuth internal constructor(
    private val client: ApiClient,
    private val storage: Storage,
    private val onIdentityChange: (String?) -> Unit,
    private val onAnonymousWipe: () -> Unit,
) {
    @Volatile private var cachedUser: SendoraCloudAuthUser? = null

    init {
        // Re-hydrate session from EncryptedSharedPreferences.
        storage.authUserJson?.let { json ->
            runCatching {
                val obj = JSONObject(json)
                cachedUser = SendoraCloudAuthUser(
                    id = obj.optString("id"),
                    email = obj.opt("email")?.takeIf { it != JSONObject.NULL } as? String,
                    emailVerified = obj.optBoolean("emailVerified", false),
                    name = obj.opt("name")?.takeIf { it != JSONObject.NULL } as? String,
                    isAnonymous = obj.optBoolean("isAnonymous", false),
                )
                cachedUser?.let { onIdentityChange(it.id) }
            }
        }
    }

    val currentUser: SendoraCloudAuthUser? get() = cachedUser
    val accessToken: String? get() = storage.authAccessToken

    suspend fun signInAnonymously(
        name: String? = null,
        metadata: Map<String, Any>? = null,
    ): Result<SendoraCloudAuthUser> {
        val body = mutableMapOf<String, Any?>()
        name?.let { body["name"] = it }
        metadata?.let { body["metadata"] = it }
        return callAuth("/auth-service/anonymous", body)
    }

    suspend fun signUp(
        email: String,
        password: String,
        name: String? = null,
        metadata: Map<String, Any>? = null,
    ): Result<SendoraCloudAuthUser> {
        val isAnonymous = currentUser?.isAnonymous == true
        val refresh = storage.authRefreshToken
        if (isAnonymous && refresh != null) {
            val body = mutableMapOf<String, Any?>(
                "refreshToken" to refresh,
                "email" to email,
                "password" to password,
            )
            name?.let { body["name"] = it }
            return callAuth("/auth-service/upgrade", body)
        }
        val body = mutableMapOf<String, Any?>("email" to email, "password" to password)
        name?.let { body["name"] = it }
        metadata?.let { body["metadata"] = it }
        return callAuth("/auth-service/signup", body)
    }

    suspend fun signIn(email: String, password: String): Result<SendoraCloudAuthUser> {
        val wasAnonymous = currentUser?.isAnonymous == true
        val response = client.post("/auth-service/login", mapOf("email" to email, "password" to password))
        val err = parseError(response)
        if (err != null) return Result.failure(err)
        val (user, _) = parseSuccess(response)
            ?: return Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        if (wasAnonymous) wipeLocalIdentity()
        persist(response!!)
        return Result.success(user)
    }

    suspend fun signOut() {
        val refresh = storage.authRefreshToken
        if (refresh != null) {
            runCatching {
                client.post("/auth-service/token/revoke", mapOf("refreshToken" to refresh))
            }.onFailure { SendoraCloudLogger.debug("signOut revoke best-effort failed: ${it.message}") }
        }
        wipeLocalIdentity()
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
        val user = SendoraCloudAuthUser(
            id = userMap["id"] as? String ?: "",
            email = userMap["email"] as? String,
            emailVerified = userMap["emailVerified"] as? Boolean ?: false,
            name = userMap["name"] as? String,
            isAnonymous = userMap["isAnonymous"] as? Boolean ?: false,
        )
        return user to tokensMap
    }

    private fun persist(response: Map<String, Any?>) {
        val (user, tokens) = parseSuccess(response) ?: return
        cachedUser = user
        storage.authAccessToken = tokens["accessToken"] as? String ?: ""
        storage.authRefreshToken = tokens["refreshToken"] as? String ?: ""
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

    private fun wipeLocalIdentity() {
        cachedUser = null
        storage.clearAuthTokens()
        onAnonymousWipe()
    }
}
