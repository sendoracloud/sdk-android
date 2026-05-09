package com.sendoracloud.sdk

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import com.sendoracloud.sdk.internal.ApiClient
import com.google.android.gms.location.Geofence
import com.google.android.gms.location.GeofencingClient
import com.google.android.gms.location.GeofencingEvent
import com.google.android.gms.location.GeofencingRequest
import com.google.android.gms.location.LocationServices
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONArray

/**
 * Server-managed geofences for Android. Operator defines circular
 * regions in the dashboard; SDK pulls active list at `start()`,
 * registers each with `GeofencingClient`, and reports enter/exit/dwell
 * transitions back to the backend.
 *
 * Android cap: **100 geofences per app**. SDK trims to head by
 * priority (lower wins).
 *
 * Permissions required (host app declares + requests at runtime):
 *   - `ACCESS_FINE_LOCATION`
 *   - `ACCESS_BACKGROUND_LOCATION` (Q+) for transitions while app is killed
 *
 * Host app dependency: `com.google.android.gms:play-services-location`
 * (the SDK doesn't add it as transitive — host app declares).
 *
 * Usage:
 * ```kotlin
 * SendoraCloud.geofences?.start(applicationContext)
 * SendoraCloud.geofences?.refresh(applicationContext)  // on foreground
 * ```
 */
class SendoraCloudGeofences internal constructor(
    private val client: ApiClient,
    private val configProvider: () -> SendoraCloudConfig?,
    private val userIdProvider: () -> String?,
    private val anonIdProvider: () -> String?,
) {
    /** Google's hard cap. SDK trims to head-by-priority. */
    private val androidGeofenceCap = 100
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private fun client(context: Context): GeofencingClient =
        LocationServices.getGeofencingClient(context.applicationContext)

    /**
     * Start monitoring. Pulls active list + registers with the OS.
     * Caller must already hold ACCESS_FINE_LOCATION (and
     * ACCESS_BACKGROUND_LOCATION on Q+).
     */
    fun start(context: Context) {
        refresh(context)
    }

    /** Re-pull + reconcile. Call on app foreground or after operator
     *  may have changed geofences server-side. */
    fun refresh(context: Context) {
        scope.launch {
            val res = client.get("/push/geofences/list-for-device")
            val data = res?.get("data") as? List<*> ?: emptyList<Any>()
            val active = data.filterIsInstance<Map<String, Any>>().take(androidGeofenceCap)
            applyRegions(context, active)
        }
    }

    /** Stop monitoring all SDK-registered geofences. */
    fun stop(context: Context) {
        client(context).removeGeofences(broadcastIntent(context))
    }

    private fun applyRegions(context: Context, active: List<Map<String, Any>>) {
        if (active.isEmpty()) return
        val list = mutableListOf<Geofence>()
        for (entry in active) {
            val id = entry["id"] as? String ?: continue
            val lat = (entry["latitude"] as? Number)?.toDouble() ?: continue
            val lng = (entry["longitude"] as? Number)?.toDouble() ?: continue
            val radius = (entry["radiusMeters"] as? Number)?.toFloat() ?: continue
            val triggers = (entry["triggers"] as? List<*>)?.filterIsInstance<String>() ?: listOf("enter")
            val dwellMs = ((entry["dwellMs"] as? Number)?.toInt()) ?: 300_000

            var transitionTypes = 0
            if ("enter" in triggers) transitionTypes = transitionTypes or Geofence.GEOFENCE_TRANSITION_ENTER
            if ("exit" in triggers) transitionTypes = transitionTypes or Geofence.GEOFENCE_TRANSITION_EXIT
            if ("dwell" in triggers) transitionTypes = transitionTypes or Geofence.GEOFENCE_TRANSITION_DWELL

            val gf = Geofence.Builder()
                .setRequestId("sendora:$id")
                .setCircularRegion(lat, lng, radius)
                .setExpirationDuration(Geofence.NEVER_EXPIRE)
                .setTransitionTypes(transitionTypes)
                .apply { if ("dwell" in triggers) setLoiteringDelay(dwellMs) }
                .build()
            list.add(gf)
        }
        if (list.isEmpty()) return

        val request = GeofencingRequest.Builder()
            // ENTER not auto-fired for already-inside fences (avoid spam).
            .setInitialTrigger(0)
            .addGeofences(list)
            .build()

        try {
            client(context).addGeofences(request, broadcastIntent(context))
        } catch (_: SecurityException) {
            // Host app missing ACCESS_FINE_LOCATION — silent fail; the
            // operator will see no geofence events flow through.
        }
    }

    private fun broadcastIntent(context: Context): PendingIntent {
        val intent = Intent(SENDORA_GEOFENCE_ACTION).setPackage(context.packageName)
        // FLAG_MUTABLE because the GeofencingEvent payload is attached
        // by the OS at trigger time. PendingIntent.FLAG_UPDATE_CURRENT
        // so re-registers don't accumulate stale intents.
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        return PendingIntent.getBroadcast(context, 0, intent, flags)
    }

    /**
     * Host app's BroadcastReceiver calls this from `onReceive()`. The
     * SDK parses the GeofencingEvent + reports each transition back to
     * the backend. Returns true on consumed.
     *
     * Host-app pattern:
     * ```kotlin
     * class MyGeofenceReceiver : BroadcastReceiver() {
     *     override fun onReceive(context: Context, intent: Intent) {
     *         SendoraCloud.geofences?.handleBroadcast(intent)
     *     }
     * }
     * ```
     * + register in AndroidManifest.xml with `<intent-filter>` matching
     * `com.sendoracloud.GEOFENCE_TRANSITION`.
     */
    fun handleBroadcast(intent: Intent): Boolean {
        val event = GeofencingEvent.fromIntent(intent) ?: return false
        if (event.hasError()) return false
        val transition = event.geofenceTransition
        val triggered = event.triggeringGeofences ?: return false
        val eventName = when (transition) {
            Geofence.GEOFENCE_TRANSITION_ENTER -> "enter"
            Geofence.GEOFENCE_TRANSITION_EXIT -> "exit"
            Geofence.GEOFENCE_TRANSITION_DWELL -> "dwell"
            else -> return false
        }
        val location = event.triggeringLocation
        scope.launch {
            for (gf in triggered) {
                val id = gf.requestId.removePrefix("sendora:")
                val body = mutableMapOf<String, Any?>(
                    "geofenceId" to id,
                    "event" to eventName,
                )
                location?.let {
                    body["latitude"] = it.latitude
                    body["longitude"] = it.longitude
                    body["accuracy"] = it.accuracy.toDouble()
                }
                userIdProvider()?.let { body["userId"] = it }
                anonIdProvider()?.let { body["anonymousId"] = it }
                client.post("/push/geofences/event", body)
            }
        }
        return true
    }

    companion object {
        const val SENDORA_GEOFENCE_ACTION = "com.sendoracloud.GEOFENCE_TRANSITION"
    }
}
