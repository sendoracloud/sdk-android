# sdk-android

Published at `github.com/sendoracloud/sdk-android`, consumed via JitPack (`com.github.sendoracloud:sdk-android:1.0.2`). Kotlin 1.9+, minSdk 26.

## Public API

```kotlin
SendoraCloud.init(context, apiKey, projectId, options)
SendoraCloud.handleDeepLink(intent|uri)
SendoraCloud.checkDeferredDeepLink(callback)
SendoraCloud.trackEvent(name, properties)
SendoraCloud.identify(userId, traits, options)
SendoraCloud.consent.grant() / revoke()
SendoraCloud.auth?.signIn / signUp / sendMagicLink / verifyEmailOtp / enrollMfa / ...
SendoraCloud.passkeys?.register(activity) / authenticate(activity, email)   // API 28+
```

## Passkeys (s51)

`SendoraCloudPasskeys` wraps androidx.credentials Credential Manager. `register(activity)` enrolls a passkey for the signed-in user (Bearer auth → backend WebAuthn round-trip). `authenticate(activity)` is the LOGIN flow (no auth, optional email hint). `isAvailable()` returns true on API 28+ where Credential Manager + Play Services 23.40+ surface the system passkey UI; older devices fail-fast with `PlatformUnsupported`. SDK `minSdk` stays at 26 (gated at runtime).

## Security

- `SendoraValidator` refuses `sk_` keys, non-HTTPS URLs, bad event names.
- `EncryptedSharedPreferences` (AES256-GCM, AndroidKeyStore master) for userId + deviceId.
- Event queue persisted with PII stripped.
- `network_security_config.xml` disables cleartext.

## Geofences (s58.22)

Server-managed geofences via `GeofencingClient` (Google Play Services). Operator defines circular regions in the dashboard; SDK auto-fetches + registers up to **100** regions.

**Permission requirements:**
- `ACCESS_FINE_LOCATION` (runtime).
- `ACCESS_BACKGROUND_LOCATION` on API 29+ (background transitions).
- Host app must include `com.google.android.gms:play-services-location:21.3.0` (SDK declares `compileOnly` to avoid forcing the dep on customers without geofences).

**Host-app pattern:**
```kotlin
// Application.onCreate or after permission grant
SendoraCloud.geofences?.start(applicationContext)

// On app foreground
SendoraCloud.geofences?.refresh(applicationContext)
```

**BroadcastReceiver wiring** — the SDK uses an Intent action `com.sendoracloud.GEOFENCE_TRANSITION`. Add a receiver:
```kotlin
class MyGeofenceReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        SendoraCloud.geofences?.handleBroadcast(intent)
    }
}
```
+ in AndroidManifest.xml:
```xml
<receiver android:name=".MyGeofenceReceiver" android:exported="false">
    <intent-filter>
        <action android:name="com.sendoracloud.GEOFENCE_TRANSITION" />
    </intent-filter>
</receiver>
```

Enter / exit / dwell transitions emit `geofence.entered` / `.exited` / `.dwelled` events; wire workflows server-side to fire push.

**Notes:**
- Aggressive OEMs (Xiaomi, Huawei) may delay transitions until the user opens the app — Battery Optimization quirk.
- 100-region cap is per-app, shared with any other `GeofencingClient` registrations the host app makes.

## Live Updates (s58.21)

Cross-platform Live Activities. Android equivalent of iOS ActivityKit, implemented via FCM data-only push routed to host-app's `FirebaseMessagingService` which updates a `NotificationCompat` ongoing notification.

**Why FCM data-only:** Android has no APNs `push-type=liveactivity` equivalent. Persistent live UIs use a regular ongoing notification updated via `NotificationManager.notify()`. Data-only push wakes the app even in Doze (priority HIGH).

**Recommended surface:** `NotificationCompat.ProgressStyle` (API 34+) for delivery / install / countdown UIs; `BigTextStyle` fallback for older Android.

**Host-app pattern:**

```kotlin
// At app start
SendoraCloud.liveActivities?.ensureChannel(applicationContext)

// When opening a live notification
SendoraCloud.liveActivities?.start(
    fcmToken = currentFcmToken,
    activityType = "OrderTracker",
    attributes = mapOf("orderId" to "1234"),
    contentState = mapOf("status" to "preparing", "minutesAway" to 30),
    externalId = "order-1234",
    userId = "user-42",
) { activityId -> /* persist activityId for later end() */ }

// In FirebaseMessagingService.onMessageReceived
class MyFcm : FirebaseMessagingService() {
    override fun onMessageReceived(message: RemoteMessage) {
        SendoraCloud.liveActivities?.handleFcmMessage(
            applicationContext,
            message.data,
            buildNotification = { contentState ->
                NotificationCompat.Builder(this, "sendora_live_updates")
                    .setSmallIcon(R.drawable.ic_status)
                    .setContentTitle("Order #${contentState.optString("orderId")}")
                    .setContentText("Status: ${contentState.optString("status")}")
                    .setOngoing(true)
                    .setOnlyAlertOnce(true)
                    .build()
            },
        )
    }
}
```

**Server-side update + end** — same endpoints as iOS (`/push/live-activities/:id/update`, `DELETE /:id`). Backend routes to FCM when `platform=android`.

**Notable Android quirks:**
- POST_NOTIFICATIONS runtime permission required (API 33+). Host app handles.
- Battery Optimization may delay updates on aggressive OEMs (Xiaomi, Huawei). Android lacks Apple-style update budgets.
- ProgressStyle requires API 34+; older Android uses BigTextStyle.

## Engagement time (Wave 75 — 4.1.0)

`SendoraCloud.trackScreen(name, properties)` emits `screen.viewed` and flushes
the previous screen's `app.engagement { durationMs, screen, sessionId }`
(foreground-only). New `autoTrackEngagement` config flag (default on).
ProcessLifecycleOwner `onStop` flushes + pauses, `onStart` resumes. Durations
use `SystemClock.elapsedRealtime()` (monotonic — immune to wall-clock / NTP
jumps); state guarded by an `engLock` monitor; spans <250ms dropped, >6h
clamped, emit outside the lock. **No Activity/Fragment auto-instrumentation** —
you name real screens so the data stays clean. Matches GA4
`engagement_time_msec`; powers `/analytics/engagement`.

## Deep Links no-app routing mode (s58.208)

`LinkCreateInput` gains an optional `noAppMode: String?` (`"auto"`/`"store"`/`"web"`)
forwarded as `noAppMode` on `POST /sdk/links`. Controls what a **mobile visitor
without the app installed** gets: `auto` (default) = store-if-registered-else-web,
`store` = prefer store, `web` = force the web fallback even when a store URL
exists. `null` inherits the project default. Additive + backwards-compatible.
Desktop is always web.

## Publish

Tag a new version; JitPack builds on first consumer request. Gradle wrapper must be committed.
