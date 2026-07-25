package com.sendoracloud.sdk

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.sendoracloud.sdk.internal.ApiClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Android Live-Update helper. Mirrors iOS Live Activities (ActivityKit)
 * via FCM data-only pushes routed to NotificationCompat.
 *
 * Usage in host app:
 *
 * 1. Register a "live updates" notification channel at app start.
 * 2. Call `SendoraCloud.liveActivities?.start(...)` when you want to
 *    open a live notification (e.g. order placed).
 * 3. In your `FirebaseMessagingService.onMessageReceived`, forward
 *    the message to `handleFcmMessage(remoteMessage.data)`. The
 *    helper updates / dismisses the notification per `event=update|end`.
 * 4. Call `end(activityId)` server-side when the workflow finishes
 *    (or rely on Sendora's API to push event=end).
 *
 * Why FCM data-only:
 *   Android has no APNs push-type=liveactivity equivalent. Persistent
 *   live UIs use a regular ongoing notification that the host app
 *   updates via NotificationManager.notify. FCM data-only push wakes
 *   the app even in Doze (priority HIGH).
 *
 * NotificationCompat.ProgressStyle (API 34+) is the recommended
 * surface for delivery / install / countdown UIs. SDK doesn't enforce
 * a renderer — the host app builds the notification it wants.
 */
class SendoraCloudLiveActivities internal constructor(
    private val client: ApiClient,
    private val configProvider: () -> SendoraCloudConfig?,
) {
    /** Channel id used by the SDK's default builder. Host app may override. */
    var channelId: String = "sendora_live_updates"

    /** Map of activityId → notificationId so updates target the right surface. */
    private val notificationIds = mutableMapOf<String, Int>()

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Register a notification channel. Call once at app start (typically
     * in Application.onCreate). Channel is reused for every live update.
     */
    fun ensureChannel(context: Context, channelName: String = "Live updates", description: String? = null) {
        val mgr = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(channelId, channelName, NotificationManager.IMPORTANCE_DEFAULT).apply {
            this.description = description
        }
        mgr.createNotificationChannel(channel)
    }

    /**
     * Register a started Live Activity with Sendora. Persists the
     * device's current FCM token + initial state on the backend.
     * Subsequent server-side updates dispatch FCM data-only push to
     * this device.
     *
     * @param fcmToken Current FCM token from the device.
     * @param activityType Stable name (e.g. "OrderTracker").
     * @param attributes Immutable per-activity payload.
     * @param contentState Initial mutable state.
     * @param externalId Optional correlation id (e.g. "order-1234").
     * @param userId Optional Sendora user id.
     * @param onResult Receives the Sendora activity id on success, null on failure.
     */
    fun start(
        fcmToken: String,
        activityType: String,
        attributes: Map<String, Any>,
        contentState: Map<String, Any>,
        externalId: String? = null,
        userId: String? = null,
        onResult: (String?) -> Unit = {},
    ) {
        val cfg = configProvider() ?: return onResult(null)
        scope.launch {
            val body = mutableMapOf<String, Any?>(
                "platform" to "android",
                "pushToken" to fcmToken,
                "activityType" to activityType,
                "attributes" to attributes,
                "contentState" to contentState,
            )
            cfg.projectId?.let { body["projectId"] = it }
            externalId?.let { body["externalId"] = it }
            userId?.let { body["userId"] = it }

            val res = client.post("/push/live-activities/start-token", body)
            val data = res?.get("data") as? Map<*, *>
            val activityId = data?.get("id") as? String
            onResult(activityId)
        }
    }

    /**
     * Handle an incoming FCM data-only message. Returns true when the
     * payload was consumed by Sendora; false otherwise (host app
     * should fall through to its own notification logic).
     *
     * Host app pattern:
     * ```kotlin
     * override fun onMessageReceived(message: RemoteMessage) {
     *     val handled = SendoraCloud.liveActivities?.handleFcmMessage(
     *         applicationContext,
     *         message.data,
     *         buildNotification = { contentState ->
     *             NotificationCompat.Builder(this, "sendora_live_updates")
     *                 .setSmallIcon(R.drawable.ic_status)
     *                 .setContentTitle("Order #${contentState.optString("orderId")}")
     *                 .setContentText("Status: ${contentState.optString("status")}")
     *                 .setOngoing(true)
     *                 .build()
     *         },
     *     ) ?: false
     *     if (!handled) { /* fall through */ }
     * }
     * ```
     */
    fun handleFcmMessage(
        context: Context,
        data: Map<String, String>,
        buildNotification: (contentState: JSONObject) -> android.app.Notification,
    ): Boolean {
        val activityId = data["sendoraLiveActivityId"] ?: return false
        val event = data["sendoraLiveActivityEvent"] ?: "update"
        val contentStateJson = JSONObject(data["sendoraContentState"] ?: "{}")

        val notificationId = notificationIds.getOrPut(activityId) {
            // Stable hash of activityId → int. Same activityId always
            // resolves to the same notification slot so updates
            // overwrite rather than stack.
            activityId.hashCode()
        }

        val mgr = NotificationManagerCompat.from(context)
        if (event == "end") {
            mgr.cancel(notificationId)
            notificationIds.remove(activityId)
            return true
        }

        // Permission check is host-app responsibility on API 33+. The
        // try/catch swallows SecurityException for older code paths.
        try {
            @Suppress("MissingPermission")
            mgr.notify(notificationId, buildNotification(contentStateJson))
        } catch (_: SecurityException) {
            return false
        }
        return true
    }

    /**
     * Cancel the local notification for an activity without server
     * round-trip. Use when the host app knows the activity is done
     * (e.g. order delivered locally) before the server-side end push
     * arrives.
     */
    fun dismissLocally(context: Context, activityId: String) {
        val notificationId = notificationIds.remove(activityId) ?: return
        NotificationManagerCompat.from(context).cancel(notificationId)
    }

    /**
     * Build a default ProgressStyle notification when no host-app
     * builder is supplied. ProgressStyle is API 34+; older Android
     * falls back to BigTextStyle.
     */
    fun defaultProgressNotification(
        context: Context,
        title: String,
        body: String,
        progress: Int = 0,
        max: Int = 100,
    ): NotificationCompat.Builder {
        return NotificationCompat.Builder(context, channelId)
            .setContentTitle(title)
            .setContentText(body)
            .setProgress(max, progress, false)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
    }
}
