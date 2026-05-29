package com.sendoracloud.sdk

import android.content.Context
import android.os.Build
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.SendoraCloudLogger
import com.sendoracloud.sdk.internal.Storage
import org.json.JSONObject

/**
 * WebAuthn passkey register + authenticate via androidx.credentials
 * (Credential Manager). Passkeys live in the user's Google Password
 * Manager / FIDO2 authenticator and never touch the SDK process —
 * the SDK only round-trips JSON between Sendora's backend and the
 * Credential Manager.
 *
 * API 28+ at runtime (Credential Manager itself supports back to API
 * 16, but real passkey support requires API 28 + Google Play Services
 * 23.40+). On older devices `isAvailable()` returns false and every
 * call fails fast with `PlatformUnsupported`. The SDK keeps
 * `minSdk = 26` so consumer apps don't have to bump.
 *
 * Lifecycle:
 *   register(activity)         — bearer-auth on backend.
 *      1. POST /passkeys/register/start → CreationOptions JSON
 *      2. CredentialManager.createCredential(activity, …)
 *      3. POST /passkeys/register/finish → enrolled passkey row
 *
 *   authenticate(activity, email)  — no auth on backend.
 *      1. POST /passkeys/authenticate/start → RequestOptions JSON
 *      2. CredentialManager.getCredential(activity, …)
 *      3. POST /passkeys/authenticate/finish → tokens
 *
 * The SDK also installs the new session into Storage on a successful
 * authenticate(), mirroring signIn() behaviour.
 */
class SendoraCloudPasskeys internal constructor(
    private val client: ApiClient,
    private val storage: Storage,
    private val installSession: suspend (Map<String, Any?>) -> SendoraCloudAuthUser?,
    private val wipe: suspend () -> Unit,
    /**
     * Returns the stored anon refresh token iff the local subject is
     * currently anonymous (device-takeover, s58.112). Injected by
     * SendoraCloud so we don't take a hard ref on the auth object.
     */
    private val takeoverHintProvider: () -> String? = { null },
) {
    sealed class PasskeyError(message: String) : Throwable(message) {
        class PlatformUnsupported(message: String) : PasskeyError(message)
        class UserCancelled(message: String) : PasskeyError(message)
        class CredentialManagerFailed(message: String) : PasskeyError(message)
        class Network(message: String) : PasskeyError(message)
        class Unauthorized(message: String) : PasskeyError(message)
        class Unknown(message: String) : PasskeyError(message)
    }

    /**
     * Whether the running device + Play Services version exposes a usable
     * Credential Manager. Cheap — surface to UIs that want to hide a
     * "Sign in with passkey" button on unsupported devices rather than
     * letting the user click and watch it fail.
     */
    fun isAvailable(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P

    /**
     * Register a new passkey for the currently signed-in user.
     * Caller must pass an Activity Context — Credential Manager needs
     * one to attach the system bottom sheet UI.
     */
    suspend fun register(activityContext: Context, name: String? = null): Result<RegisteredPasskey> {
        if (!isAvailable()) {
            return Result.failure(PasskeyError.PlatformUnsupported("Passkeys require Android 9 (API 28)+"))
        }
        val token = storage.authAccessToken
            ?: return Result.failure(PasskeyError.Unauthorized("Not signed in"))
        val headers = mapOf("Authorization" to "Bearer $token")

        // 1. Ask backend for CreationOptions JSON.
        val startRes = runCatching {
            client.post("/auth-service/passkeys/register/start", emptyMap(), headers)
        }.getOrElse { return Result.failure(PasskeyError.Network(it.message ?: "register/start failed")) }
        val optionsJson = (startRes?.get("data") as? Map<*, *>)
            ?: return Result.failure(PasskeyError.Unknown("Malformed register/start response"))
        val requestJson = JSONObject(optionsJson as Map<String, Any?>).toString()

        // 2. Hand off to Credential Manager.
        val mgr = CredentialManager.create(activityContext)
        val createRequest = CreatePublicKeyCredentialRequest(requestJson)
        val cmResp = runCatching {
            mgr.createCredential(activityContext, createRequest)
        }.getOrElse { e ->
            return Result.failure(mapCreateError(e))
        }
        val responseJson = (cmResp as? CreatePublicKeyCredentialResponse)?.registrationResponseJson
            ?: return Result.failure(PasskeyError.CredentialManagerFailed("Empty Credential Manager response"))

        // 3. Ship back to backend for verification + storage.
        val parsed = runCatching { JSONObject(responseJson) }.getOrNull()
            ?: return Result.failure(PasskeyError.CredentialManagerFailed("Non-JSON Credential Manager response"))
        val finishBody = mutableMapOf<String, Any?>("response" to parsed.toMap())
        if (!name.isNullOrBlank()) finishBody["name"] = name
        val finishRes = runCatching {
            client.post("/auth-service/passkeys/register/finish", finishBody, headers)
        }.getOrElse { return Result.failure(PasskeyError.Network(it.message ?: "register/finish failed")) }
        val data = finishRes?.get("data") as? Map<*, *>
            ?: return Result.failure(PasskeyError.Unknown("Malformed register/finish response"))
        val id = data["id"] as? String
            ?: return Result.failure(PasskeyError.Unknown("Server omitted passkey id"))
        return Result.success(
            RegisteredPasskey(
                id = id,
                name = data["name"] as? String,
                createdAt = data["createdAt"] as? String,
            ),
        )
    }

    /**
     * Sign in with a passkey. Optional `email` hint lets the OS pre-
     * filter to a single account when the user has multiple.
     */
    suspend fun authenticate(activityContext: Context, email: String? = null): Result<SendoraCloudAuthUser> {
        if (!isAvailable()) {
            return Result.failure(PasskeyError.PlatformUnsupported("Passkeys require Android 9 (API 28)+"))
        }
        if (!storage.isSecureAvailable) {
            return Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }

        // 1. Backend hands us the WebAuthn challenge. Requires either
        //    an API key auth header (handled by ApiClient) — passkey
        //    auth is the LOGIN flow so the Bearer token doesn't exist
        //    yet. The endpoint accepts an optional email to scope.
        val startBody = if (email.isNullOrBlank()) emptyMap() else mapOf("email" to email)
        val startRes = runCatching { client.post("/auth-service/passkeys/authenticate/start", startBody) }
            .getOrElse { return Result.failure(PasskeyError.Network(it.message ?: "authenticate/start failed")) }
        val optionsJson = (startRes?.get("data") as? Map<*, *>)
            ?: return Result.failure(PasskeyError.Unknown("Malformed authenticate/start response"))
        val requestJson = JSONObject(optionsJson as Map<String, Any?>).toString()

        // 2. Wipe any prior identity BEFORE the credential prompt so a
        //    track() during the prompt doesn't bind to the previous
        //    user.
        wipe()

        // 3. Credential Manager.
        val mgr = CredentialManager.create(activityContext)
        val getRequest = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson)))
        val cmResp = runCatching { mgr.getCredential(activityContext, getRequest) }
            .getOrElse { e -> return Result.failure(mapGetError(e)) }
        val cred = cmResp.credential as? PublicKeyCredential
            ?: return Result.failure(PasskeyError.CredentialManagerFailed("Credential is not a passkey"))
        val responseJson = cred.authenticationResponseJson

        // 4. Verify + mint session.
        val parsed = runCatching { JSONObject(responseJson) }.getOrNull()
            ?: return Result.failure(PasskeyError.CredentialManagerFailed("Non-JSON authentication response"))
        val finishBody = mutableMapOf<String, Any>("response" to parsed.toMap())
        // Device-takeover (s58.112): if device currently anonymous,
        // forward the anon refresh so backend retires anon row.
        takeoverHintProvider()?.let { finishBody["prevAnonRefreshToken"] = it }
        val finishRes = runCatching {
            client.post("/auth-service/passkeys/authenticate/finish", finishBody)
        }.getOrElse { return Result.failure(PasskeyError.Network(it.message ?: "authenticate/finish failed")) }

        @Suppress("UNCHECKED_CAST")
        val payload = finishRes?.get("data") as? Map<String, Any?>
            ?: return Result.failure(PasskeyError.Unknown("Malformed authenticate/finish response"))
        val installed = installSession(payload)
            ?: return Result.failure(PasskeyError.Unknown("Failed to install session"))
        return Result.success(installed)
    }

    private fun mapCreateError(e: Throwable): Throwable {
        if (e is CreateCredentialException) {
            SendoraCloudLogger.error("Passkey register failed: ${e.type}", e)
            return when (e.type) {
                "android.credentials.CreateCredentialException.TYPE_USER_CANCELED" ->
                    PasskeyError.UserCancelled(e.message ?: "User cancelled")
                else -> PasskeyError.CredentialManagerFailed(e.message ?: e.type)
            }
        }
        return PasskeyError.Unknown(e.message ?: "Unknown register failure")
    }

    private fun mapGetError(e: Throwable): Throwable {
        if (e is GetCredentialException) {
            SendoraCloudLogger.error("Passkey authenticate failed: ${e.type}", e)
            return when (e.type) {
                "android.credentials.GetCredentialException.TYPE_USER_CANCELED" ->
                    PasskeyError.UserCancelled(e.message ?: "User cancelled")
                "android.credentials.GetCredentialException.TYPE_NO_CREDENTIAL" ->
                    PasskeyError.CredentialManagerFailed("No matching passkey found on this device")
                else -> PasskeyError.CredentialManagerFailed(e.message ?: e.type)
            }
        }
        return PasskeyError.Unknown(e.message ?: "Unknown authenticate failure")
    }

    data class RegisteredPasskey(
        val id: String,
        val name: String?,
        val createdAt: String?,
    )
}

private fun JSONObject.toMap(): Map<String, Any?> {
    val out = mutableMapOf<String, Any?>()
    for (key in keys()) {
        out[key] = when (val v = this.get(key)) {
            is JSONObject -> v.toMap()
            org.json.JSONObject.NULL -> null
            is org.json.JSONArray -> v.toListAny()
            else -> v
        }
    }
    return out
}

private fun org.json.JSONArray.toListAny(): List<Any?> {
    val out = mutableListOf<Any?>()
    for (i in 0 until length()) {
        out += when (val v = get(i)) {
            is JSONObject -> v.toMap()
            org.json.JSONObject.NULL -> null
            is org.json.JSONArray -> v.toListAny()
            else -> v
        }
    }
    return out
}
