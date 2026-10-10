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
import com.sendoracloud.sdk.internal.AuthTransport
import com.sendoracloud.sdk.internal.SendoraCloudLogger
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
 * The SDK also installs the new session on a successful authenticate()
 * through the auth commit funnel (ADR-033: a passkey sign-in is a SWITCH —
 * a guest on this device is HELD, never retired; the finish body carries no
 * guest hint, INV-3).
 */
class SendoraCloudPasskeys internal constructor(
    private val client: AuthTransport,
    /**
     * Whether EncryptedSharedPreferences is available — a minted session that
     * cannot be persisted securely is refused before the system sheet opens.
     */
    private val secureAvailable: () -> Boolean,
    /**
     * A FRESH Bearer token for the register flow (refreshing a past-expiry one),
     * or `null` when signed out / withheld. Injected by SendoraCloudAuth.
     */
    private val bearerProvider: suspend () -> String?,
    /**
     * Installs the minted session through `commit()` — validates it, holds a
     * guest if one was current, persists — in that order, so an assertion that
     * never completes leaves the caller signed in as whoever they were.
     */
    private val installSession: suspend (Map<String, Any?>) -> SendoraCloudAuthUser?,
) {
    /**
     * [kind] mirrors [SendoraCloudAuthErrorKind] (4.12.0) so a caller can branch
     * on one taxonomy across every sign-in path — a dismissed system sheet
     * classifies as CANCELLED here exactly as a cancelled Play Games sheet does
     * on the auth surface. The error CLASSES are unchanged.
     */
    sealed class PasskeyError(
        message: String,
        val kind: SendoraCloudAuthErrorKind,
    ) : Throwable(message) {
        /** True when retrying the SAME input can plausibly succeed later. */
        val retryable: Boolean get() = kind.retryable

        class PlatformUnsupported(message: String) : PasskeyError(message, SendoraCloudAuthErrorKind.CONFIG)
        class UserCancelled(message: String) : PasskeyError(message, SendoraCloudAuthErrorKind.CANCELLED)
        class CredentialManagerFailed(message: String) : PasskeyError(message, SendoraCloudAuthErrorKind.UNKNOWN)
        class Network(message: String) : PasskeyError(message, SendoraCloudAuthErrorKind.NETWORK)
        class Unauthorized(message: String) : PasskeyError(message, SendoraCloudAuthErrorKind.INVALID_CREDENTIAL)
        class Unknown(message: String) : PasskeyError(message, SendoraCloudAuthErrorKind.UNKNOWN)
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
        val token = bearerProvider()
            ?: return Result.failure(PasskeyError.Unauthorized("Not signed in"))
        val headers = mapOf("Authorization" to "Bearer $token")

        // 1. Ask backend for CreationOptions JSON.
        val startRes = runCatching {
            client.post("/auth-service/passkeys/register/start", emptyMap(), headers)
        }.getOrElse { return Result.failure(PasskeyError.Network(it.message ?: "register/start failed")) }
        val optionsJson = (startRes?.get("data") as? Map<*, *>)
            ?: return Result.failure(PasskeyError.Unknown("Malformed register/start response"))
        @Suppress("UNCHECKED_CAST")
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
        if (!secureAvailable()) {
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
        @Suppress("UNCHECKED_CAST")
        val requestJson = JSONObject(optionsJson as Map<String, Any?>).toString()

        // 2. Credential Manager. The prior identity stays put across the
        //    system sheet: cancelling it is a routine outcome (wrong account,
        //    no passkey on this device, back gesture), and for an anonymous
        //    user the refresh token is the only handle on their account.
        //    installSession() holds it once a session has actually been minted.
        val mgr = CredentialManager.create(activityContext)
        val getRequest = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson)))
        val cmResp = runCatching { mgr.getCredential(activityContext, getRequest) }
            .getOrElse { e -> return Result.failure(mapGetError(e)) }
        val cred = cmResp.credential as? PublicKeyCredential
            ?: return Result.failure(PasskeyError.CredentialManagerFailed("Credential is not a passkey"))
        val responseJson = cred.authenticationResponseJson

        // 3. Verify + mint session. ADR-033 INV-3: the body carries the
        //    assertion and NOTHING about the guest on this device — the guest
        //    is held locally by the commit funnel, never retired server-side.
        val parsed = runCatching { JSONObject(responseJson) }.getOrNull()
            ?: return Result.failure(PasskeyError.CredentialManagerFailed("Non-JSON authentication response"))
        val finishBody = mutableMapOf<String, Any?>("response" to parsed.toMap())
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
