# sdk-android

Published at `github.com/sendoracloud/sdk-android`, consumed via JitPack (`com.github.sendoracloud:sdk-android:1.0.2`). Kotlin 1.9+, minSdk 26.

> ⚠ **ADR-023 frozen contract.** SharedPreferences keys (`auth_*`, `event_queue`, `device_id`, `session_id`, …), the `X-Sendora-SDK-{Name,Version}` headers, and the `schema_version` marker are depended on by installed apps — never rename/remove a key (orphans session/queue on upgrade) or drop the header/marker. Version lives ONLY in `SdkVersion.kt` (must equal `build.gradle.kts`). Additive only; a format change is MAJOR + needs a migration. CI cap: `apps/backend/src/modules/developer-tools/sdk-contract-golden.test.ts`. Law: `docs/decisions/023-sdk-api-compatibility.md`.

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

## 4.8.2 — fix 3 latent Kotlin compile errors (first compiling release)

Once the 4.8.1 wrapper let JitPack reach the compiler, three never-caught compile errors surfaced (the SDK had literally never compiled): `SendoraCloud.kt` missing `import org.json.JSONObject`; a `SendoraCloudLinks.kt` prewarm waiter (non-suspend `(Result)->Unit` invoked via `forEach`) calling suspend `withContext` → switched to `scope.launch(Dispatchers.Main)`; `SendoraCloudLiveActivities.kt` `@SuppressWarnings` (java, not expression-applicable) → Kotlin `@Suppress`. **Verified with a real build** (local Android SDK + `ANDROID_HOME`): `./gradlew :publishToMavenLocal` → BUILD SUCCESSFUL, AAR published, `:compileReleaseKotlin` clean. 4.8.1's tag has a JitPack-cached failed build, so **4.8.2 is the first consumable release**. ⚠ **The monorepo has no Android SDK in CI, so nothing catches a Kotlin compile error before a JitPack publish** — build the module against a local Android SDK (`ANDROID_HOME=… ./gradlew :publishToMavenLocal`) before every mirror push.

## 4.8.1 — JitPack build fix (commit the Gradle wrapper + settings)

Every version ≤4.8.0 failed to build on JitPack (`./gradlew: No such file or directory`, exit 127) — the package shipped `jitpack.yml` + `build.gradle.kts` but no wrapper, no `settings.gradle.kts`, no `gradle.properties`. Committed the canonical Gradle **8.2** wrapper (`gradlew`/`gradlew.bat`/`gradle/wrapper/*`, jar sha256 `a8451ee…46e4` from gradle/gradle@v8.2.0) + `settings.gradle.kts` (`pluginManagement` pins **AGP 8.2.2** + **Kotlin 1.9.22**) + `gradle.properties` (`android.useAndroidX=true`). Locally proven: `./gradlew projects` → BUILD SUCCESSFUL; `:publishToMavenLocal --dry-run` reaches the AGP graph, stops only at "SDK location not found" (JitPack supplies the SDK). Source-identical to 4.8.0; **4.8.1 is the first buildable release carrying the method fields.** (`ANDROID_HOME` + Android SDK are the only thing a local full build needs.)

## 4.8.0 — `signupMethod` + `lastLoginMethod` on the auth user

`SendoraCloudAuthUser` gains two optional read-only fields: `signupMethod` (how the account was first created, immutable) + `lastLoginMethod` (most recent auth). Free-form provider tokens (`password`/`anonymous`/`google`/`apple`/`gamecenter`/`playgames`/`magic_link`/`passkey`/`oidc`/…). Backend populates them on the login/signup/social/game response (s58.266, mig 0094). Nullable with `= null` defaults on the data class (a cached user from a pre-4.8.0 build still constructs); parsed from both the response map and the rehydrate JSON, and written to the persisted JSON. Display-only — never an authorization signal. No frozen SharedPreferences key/header/wire-shape touched (ADR-023); not in the golden wire contract. `build.gradle.kts` + `SdkVersion.kt` bumped in lockstep. Parity with RN 1.24.0 / web 3.8.0 / iOS 4.9.0.

## 4.7.0 — Play Games sign-in

`auth.signInWithPlayGames(serverAuthCode, link)` (suspend) — email-less, player-keyed sign-in. Pass the `serverAuthCode` from `PlayGames.getGamesSignInClient(activity).requestServerSideAccess(webClientId, false)`; forwards to `POST /auth-service/login/play-games`. Mirrors `loginSocial` (mutex, `isSecureAvailable` guard, anon-takeover hint → `prevAnonRefreshToken`, `link` → `linkAnonymous` for ADR-025 link-in-place, `callAuth`). Additive, SDK-only (not in golden wire contract). App obtains the auth-code via the Play Games SDK itself (no PGS dep forced). Ships alongside backend Phase 1 + RN 1.21.0.

## 4.6.0 — anon→social link-in-place (ADR-025)

`loginSocial` / `signInWithApple` / `signInWithGoogle` gain an opt-in `link: Boolean = false`. When anonymous + `link = true`, the anon→social upgrade sends `linkAnonymous` so the backend promotes the anon row IN PLACE — `sub` PRESERVED (fires `auth.user_upgraded`) instead of a device-takeover (new id); Firebase `linkWithCredential` parity. No effect off-anon or on a collision. Default-arg = source-compatible; additive. Design: `docs/decisions/025-anon-social-link-in-place.md`.

## 4.5.0 — SDK/API compatibility (ADR-023)

4.5.0 — ADR-023: single-source SDK_VERSION + X-Sendora-SDK-{Name,Version}
headers + schema_version marker; fix event-queue ACK-before-remove durability;
emit anonymousId for anon users (parity with iOS).

The version string used to be hardcoded as `"4.4.0"` in two places (the event
body `context.sdk` and `build.gradle.kts`) — drift risk. The ONLY source of
truth is now `internal/SdkVersion.kt` (`SDK_VERSION` / `SDK_NAME`); the event
body reads it and `build.gradle.kts` carries a comment to keep its `version` in
lockstep. `buildConfig` stays disabled — a single Kotlin const is the source of
truth (no BuildConfig machinery). Every HTTP request (`ApiClient`, both the
plain `request` and `doRichRequest` builders) now also sends
`X-Sendora-SDK-Name: sendora-android` + `X-Sendora-SDK-Version: <SDK_VERSION>`
so the backend gets a version signal on non-event routes too (auth/links/push)
— ignored today. On init, `Storage.ensureSchemaVersion()` writes plain
SharedPreferences (`sendora_sdk`) key `schema_version = "1"` if absent
(non-sensitive → plain tier, NOT EncryptedSharedPreferences), giving a future
in-place upgrade a hook to branch a local-storage migration. Read nowhere yet;
no existing key renamed (frozen per ADR-023 §3.4).

**Bug fix — event-queue durability (ACK-before-remove).**
`EventQueue.performFlush()` used to `events.clear()` BEFORE the HTTP call, so a
flush 5xx / network error permanently lost the batch. It now snapshots the
front of the queue under the lock, hands it to the flush handler OUTSIDE the
lock (so the HTTP round-trip never blocks `add()`), and only removes exactly
those snapshotted events from the FRONT (FIFO) AFTER the handler reports
success — re-persisting the remainder. On failure everything stays queued for
the next flush. An `isFlushing` guard prevents a timer-tick + threshold flush
from double-sending. The flush handler signature changed to
`suspend (events) -> Boolean` (true = backend accepted). Mirrors iOS
`EventQueue.swift`.

**Bug fix — emit anonymousId for anon users.** When there's no `userId`, the
event body now attaches `anonymousId = storage.deviceId` (only when no userId).
Matches sdk-ios. Without it the backend's `coalesce(user_id, anonymous_id)`
identity (s58.219) undercounted Android anonymous users.

## 4.4.0 — appVersion in device context (ADR-022)

`DeviceInfo.toMap()` now also emits `appVersion` (already collected from
`PackageManager.versionName`) alongside the existing `type` / `os` / `osVersion`
/ `model`. So every event's `context.device` carries the host app version,
powering the dashboard Analytics → Audience app-version breakdown. No config or
host-app change — auto-detected from the package info. The native SDKs already
led on device context; this just surfaces the app version that was being
collected but not sent.

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

## Account deletion (s58.209)

`auth.deleteAccount()` (suspend, Bearer) deletes the signed-in user's account for
Apple App Store Guideline 5.1.1(v). `Result<AccountDeletionResult>` — `status` is
`"purged"` (grace 0) or `"pending"` (disabled + sessions revoked now; hard-deleted
at `scheduledPurgeAt`, cancellable by signing back in within grace). Wipes local
identity on success. Grace period is a per-project Auth setting.

**4.3.1 — refresh-before-delete.** `deleteAccount()` now resolves a fresh access
token via `getAccessToken()` (refreshing a past-expiry cached token) BEFORE the
`DELETE` instead of reading the raw cached token via `bearerHeaders()`. Safe
under the held `mutex` because `getAccessToken()`/`refreshAccessToken()` use a
separate `refreshMutex`. This is a one-shot destructive action — a 401 from a
stale token (typical when a user taps "delete" after the app sat idle past the
short access TTL) would silently strand them with an undeleted account (cause of
prod `DELETE /auth-service/me 401`s). **Host-app note:** wire your delete button
to `auth.deleteAccount()` — NOT `consent.requestDeletion()` (GDPR ledger only).

## Deep Links no-app routing mode (s58.208)

`LinkCreateInput` gains an optional `noAppMode: String?` (`"auto"`/`"store"`/`"web"`)
forwarded as `noAppMode` on `POST /sdk/links`. Controls what a **mobile visitor
without the app installed** gets: `auto` (default) = store-if-registered-else-web,
`store` = prefer store, `web` = force the web fallback even when a store URL
exists. `null` inherits the project default. Additive + backwards-compatible.
Desktop is always web.

## Publish

Native SDKs ship via a git tag on the **separate public mirror** `github.com/sendoracloud/sdk-android` (JitPack builds on first consumer request), not npm. From a monorepo checkout:

1. Guard the version: `node scripts/publish.mjs android` (verifies `build.gradle.kts` == `SdkVersion.kt`).
2. Mirror it (operator, needs a clone of the mirror + push creds):
   `node scripts/publish-native-mirror.mjs android --mirror-dir <clone> [--push] [--delete]` — rsyncs `packages/sdk-android/` → the mirror clone (excludes `build`/`.gradle`), commits, tags `<semver>`, pushes. **DRY by default**; `--push` executes; `--delete` makes the mirror an exact copy. It refuses a wrong/monorepo mirror dir or an existing tag. First time: `git clone https://github.com/sendoracloud/sdk-android.git <clone>`. The Gradle wrapper must be committed in the mirror.

Raw path (equivalent): rsync source into the mirror clone, then `git tag <semver> && git push origin main --tags`.
