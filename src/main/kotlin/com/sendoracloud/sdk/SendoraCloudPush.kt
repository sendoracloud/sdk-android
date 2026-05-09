package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.util.Locale
import java.util.TimeZone

/**
 * Generic push-token registration. Wraps `POST /api/v1/push/tokens` so
 * host apps don't have to hand-roll OkHttp + JSON for the most common
 * flow. Live Updates have their own helper (SendoraCloudLiveActivities);
 * this module covers vanilla FCM tokens for user-facing pushes.
 *
 * Usage in FirebaseMessagingService:
 *
 * ```kotlin
 * class MyFcm : FirebaseMessagingService() {
 *     override fun onNewToken(token: String) {
 *         SendoraCloud.push?.registerToken(token) { result ->
 *             result.onSuccess { tokenId -> /* persist if needed */ }
 *             result.onFailure { err -> /* log */ }
 *         }
 *     }
 * }
 * ```
 *
 * Identify the user FIRST so the token binds to a userId — anonymous
 * tokens can't be targeted via `{ userIds: [...] }`.
 */
class SendoraCloudPush internal constructor(
    private val client: ApiClient,
    private val scope: CoroutineScope,
    private val userIdProvider: () -> String?,
) {
    enum class Platform(val wire: String) {
        /** FCM (Android, default). */
        ANDROID("android"),

        /** Web Push subscription parts. Native Android apps generally don't use this. */
        WEB("web"),
    }

    /**
     * Register an FCM token with Sendora.
     *
     * @param token FCM token from `FirebaseMessaging.getInstance().token`.
     * @param platform Defaults to [Platform.ANDROID].
     * @param userId Optional override. Defaults to currently identified user.
     * @param locale BCP-47 (e.g. "en-US"). Powers `localizedBody` resolution.
     * @param timezone IANA TZ. Powers quiet hours.
     * @param completion Returns the Sendora `tokenId` UUID on success.
     */
    fun registerToken(
        token: String,
        platform: Platform = Platform.ANDROID,
        userId: String? = null,
        locale: String? = null,
        timezone: String? = null,
        completion: ((Result<String>) -> Unit)? = null,
    ) {
        val body = mutableMapOf<String, Any?>(
            "platform" to platform.wire,
            "token" to token,
        )
        val resolvedUser = userId ?: userIdProvider()
        if (resolvedUser != null) body["userId"] = resolvedUser
        body["locale"] = locale ?: Locale.getDefault().toLanguageTag()
        body["timezone"] = timezone ?: TimeZone.getDefault().id

        scope.launch {
            try {
                val response = client.post("/push/tokens", body) ?: run {
                    completion?.invoke(Result.failure(IllegalStateException("empty response")))
                    return@launch
                }
                val success = response["success"] as? Boolean ?: false
                if (!success) {
                    val err = (response["error"] as? Map<*, *>)?.get("message") as? String ?: "unknown"
                    completion?.invoke(Result.failure(IllegalStateException(err)))
                    return@launch
                }
                val data = response["data"] as? Map<*, *>
                val tokenId = data?.get("tokenId") as? String
                if (tokenId != null) {
                    completion?.invoke(Result.success(tokenId))
                } else {
                    completion?.invoke(Result.failure(IllegalStateException("missing tokenId")))
                }
            } catch (e: Throwable) {
                completion?.invoke(Result.failure(e))
            }
        }
    }

    /**
     * Notify Sendora that a notification was opened. Host app calls this
     * from the FCM `onMessageReceived` (when payload includes
     * `sendoraSendId`) and from the launcher activity when started via
     * a notification tap.
     */
    fun trackOpen(sendId: String, clickAction: String? = null) {
        val body = mutableMapOf<String, Any?>("sendId" to sendId)
        if (clickAction != null) body["clickAction"] = clickAction
        scope.launch {
            try {
                client.post("/push/track-open", body)
            } catch (_: Throwable) {
                // Silent — tracking is best-effort.
            }
        }
    }
}
