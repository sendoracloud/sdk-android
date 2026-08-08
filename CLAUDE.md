# sdk-android

Published at `github.com/sendoracloud/sdk-android`, consumed via JitPack (`com.github.sendoracloud:sdk-android:1.0.2`). Kotlin 1.9+, minSdk 26.

> ⚠ **ADR-023 frozen contract.** SharedPreferences keys (`auth_*`, `event_queue`, `device_id`, `session_id`, …), the `X-Sendora-SDK-{Name,Version}` headers, and the `schema_version` marker are depended on by installed apps — never rename/remove a key (orphans session/queue on upgrade) or drop the header/marker. Version lives ONLY in `SdkVersion.kt` (must equal `build.gradle.kts`). Additive only; a format change is MAJOR + needs a migration. CI cap: `apps/backend/src/modules/developer-tools/sdk-contract-golden.test.ts`. Law: `docs/decisions/023-sdk-api-compatibility.md`.



## ⚠ The version lives in TWO files — keep them in lockstep

`build.gradle.kts` (`version = "..."`) **and**
`src/main/kotlin/com/sendoracloud/sdk/internal/SdkVersion.kt` (`SDK_VERSION`).

Bumping only one is silent at compile time and only surfaces at publish, where
`scripts/publish.mjs android` refuses with "version mismatch across source
files". That guard is the only thing standing between a release and an SDK that
announces the OLD version in its `X-Sendora-SDK-Version` header while published
under the new one — which corrupts every version-correlated support question
without ever failing a build. It caught exactly this on the 4.18.0 bump.


## 4.18.0 — getLastAnonRetirement(): did my guest account survive? (s58.278)

Parity: RN 1.33.0 / web 3.17.0 / iOS 4.18.0. Additive; no behaviour change to any existing call.

`retiredAnonUserId` is present-or-absent, and the absence covered two
situations that need opposite handling: the guest account was retired but not
named, versus nothing was retired and the guest is still alive and claimable.
A customer hit exactly that — saw no `retiredAnonUserId` after an adopt and
had to ask us which it was, because it is not answerable from outside (the
device-takeover's no-ops are silent by design).

Sign-in responses now carry `anonRetirement`, and `getLastAnonRetirement()`
returns the last value (cleared on sign-out):

- `retired` — the guest row was deleted; its id arrives via `onDeviceTakeover`.
- `preserved` — a guest token WAS sent and the guest was NOT retired. That
  account still exists, so "recover your other account" is a real offer.
- `none` — no guest token was sent; nothing to reconcile.

⚠ The value is recorded ONLY when the server states it. An older backend omits
the field entirely, and treating that as `none` would assert a fact we were
never told — absent and `none` are different answers.

## 4.17.0 — the collision default is now safe by construction (s58.274)

Parity: RN 1.32.0 / web 3.16.0 / iOS 4.17.0. **Behaviour change to the DEFAULT** — see below for who it affects (in practice: nobody with real users).

`onCredentialInUse` shipped in the previous release with a default of `adopt`, kept
for compatibility. That was the wrong call: the destructive path was what you got by
not knowing the option existed, and it succeeded silently, so there was no error to
prompt a second look. The next integrator would have had to lose an account to learn.

**The hazard was never "a collision happened" — it is "a collision happened AND
adopting would DELETE a live guest account on this device".** Those deserve different
answers, and now get them:

- **Fresh install / no guest session** → nothing to lose, so it adopts. This is the
  reinstall-recovery path, and it is never refused.
- **Live guest session** → adopting would retire it (row deleted). Refused with
  `CREDENTIAL_IN_USE` so the app can ask the player.

So the safe behaviour is now the behaviour, and `onCredentialInUse` becomes a pure
override: `"adopt"` to switch anyway (the old semantics), `"reject"` to fail on any
collision at all.

⚠ **If you relied on silent adopt** — i.e. you consume the device-takeover signal to
migrate progress on a returning player — pass `onCredentialInUse: "adopt"` explicitly.
Everything else is unchanged: the adopt path still retires the row and still fires the
takeover webhook.


## 4.16.0 — onDeviceTakeover doc fix: the account-deleting paths were missing (s58.273)

Parity: RN 1.31.0 / web 3.15.0 / iOS 4.16.0. **Documentation-only in the SDK; no behaviour change.**

Customer-reported (Word Hurdle). The doc comment on `onDeviceTakeover` enumerated
where the listener fires — signIn / loginSocial / verifyMagicLink / verifyEmailOtp
/ challengeMfa / passkey / SSO — and **omitted the Game Center and Play Games
paths, the only ones that can DELETE an account.** It does fire there (centrally,
from the persist path), so this was purely a doc defect; but an integrator reading
that list would reasonably conclude a gaming adopt produces no takeover and skip
the one handler that path most needs. That is the path that destroys accounts.

The comment now names the gaming sign-ins explicitly and states the consequence:
a takeover means the anonymous account was retired — its row DELETED server-side
— while **the call itself resolved successfully**, so this listener is the only
client-side signal. It also points at `onCredentialInUse: reject` for callers
who would rather it not happen.

Guarded so the list cannot drift again: `credential-collision.test.ts` asserts
each SDK's doc block (the 1600 chars immediately above the declaration, not the
whole file) names its gaming path. Mutation-proven — redacting the tokens from
all four doc windows fails 4.

## 4.15.0 — credential-collision policy + anonymous link promotion (s58.272)

Parity: RN 1.30.0 / web 3.14.0 / iOS 4.15.0. Full write-up in the RN CLAUDE.md 1.30.0 section.

- **`onCredentialInUse` (`adopt`|`reject`)** on the credentialed sign-in
  methods. **Omitted = adopt = every prior release** (no field is sent). On a
  collision the sign-in ADOPTS the owning account and — because the anon refresh
  hint is forwarded whenever the local user is anonymous — the server hard-deletes
  this device's anonymous row. That is a 200, so the wipe-ordering fix never
  covered it. `reject` fails with the credential-in-use error and changes nothing.
- **The collision error carries the taxonomy** (`kind`/`retryable`/`code`/`status`)
  plus `provider` + `collision` (`identity`|`email`).
- **Linking from an ANONYMOUS session** promotes the account in place (sub
  preserved) and the server ROTATES the session, because the `is_anonymous` JWT
  claim changed. The link path installs the returned `tokens` when the response
  carries `upgraded: true` — **not optional**, the old refresh token is revoked
  server-side. An identified link is unchanged (no tokens, cached user updated in
  place). Firebase `linkWithCredential` / Supabase `linkIdentity` parity.

`CredentialCollisionPolicy` is a defaulted (`null`) parameter on `loginSocial` +
`signInWithPlayGames`, so every existing call site compiles unchanged.
`:publishToMavenLocal` + `testDebugUnitTest` green.

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

## 4.14.0 — anonymous-session reuse + total error coercion (s58.271d)

Parity with RN 1.29.0 / web 3.13.0 / iOS 4.14.0.

- **A corrupt user blob is now actually recoverable.** Keeping the refresh token
  when the cached user fails to parse was only half a fix: nothing could turn
  that token back into an identity, because the refresh discarded the `user` the
  backend returns in the very same response — so the session sat live with a
  permanently null user and the next sign-in orphaned the account anyway. The
  refresh now adopts that user, but **only when there is none** (a refresh is a
  token rotation, not an identity change), only when it is well-formed (the
  route tolerates a missing user row), and it emits `signed_in` because
  recovering an identity IS a transition — while a plain rotation with a user
  already present still emits nothing.

- **`signInAnonymously()` reuses an existing anonymous session.** It minted a
  brand-new user unconditionally, and `persist()` overwrote the stored refresh
  token — the previous anonymous account's ONLY durable handle — with no
  takeover, no webhook and no state event. An app calling it defensively on
  every cold launch (the most natural thing to write) fragmented the player
  across a new `user_id` per launch: the same lost-progress outcome as a failed
  sign-in wiping the session, except on a **healthy** network. Now short-circuits
  when the cached user is anonymous AND a refresh token is on disk (Firebase's
  `signInAnonymously` does exactly this). Opt out with `forceNew`.
- **Every rejection carries a `kind`.** A new `asAuthError` coercion at the
  op boundary maps a timeout to `kind: network` and anything unmapped to
  `kind: unknown`. **The default must stay non-fatal** — that is what makes the
  one-code `isDeadRefreshError` allow-list safe rather than lucky: an unmapped
  failure can only become session-fatal through a deliberate edit. Firebase
  enforces the same rule at its HTTP boundary, with a comment warning that
  changing it logs users out on network errors. Typed errors shipped apps match
  with `instanceof` (`EmailAlreadyTaken` / `AlreadyIdentified` /
  `CredentialInUse`) pass through untouched.

Both gaps came from a cross-SDK architecture study (Firebase, Supabase, Auth0,
Clerk, Amplify/Cognito, RevenueCat) read against our own source. The anonymous
overwrite was independently flagged by the adversarial review of s58.271.

`forceNew: Boolean = false` is a defaulted third argument (source-compatible). Coercion is applied at three shapes, not one: `serialize` (mutex + coercion, so a newly added mutating op cannot miss it), `guardedResult` (the 9 unlocked `Result` ops), and `guardedValue`. **`CancellationException` is rethrown BEFORE the catch-all** — Kotlin structured concurrency requires it, and reporting a cancelled coroutine as a `Result.failure` would let abandoned work report back. Android's transport already returned `null` on timeout (→ `Network`), so as on web this is the general rule rather than a symptom fix. Tests: `AuthErrorCoercionTest` 8/8 + `ApiClientEnvelopeTest` 10/10. The reuse guard is pinned by source assertions (instantiating the class needs a Context-backed Storage); the pin was mutation-tested by deleting the guard.

## 4.14.0 — token refresh shape + the remaining loss routes (s58.271b)

Parity with RN 1.29.0 / web 3.13.0 / iOS 4.14.0. See the RN CLAUDE.md 1.29.0
section for the full write-up.

- **⚠ `/token/refresh` shape (CRITICAL, pre-existing).** `refreshAccessToken`
  read `data["accessToken"]`, but the rotated trio lives under `data.tokens`
  (flat was abandoned in s58.76). Refresh silently returned null forever — the
  session died at access-token expiry and the app minted a fresh guest, the same
  account loss 4.12.0 exists to prevent. Both levels accepted now.
- **A generic 401 no longer wipes the session.** `isDeadRefreshError` narrowed to
  `INVALID_REFRESH_TOKEN`; `UNAUTHORIZED`/`HTTP_401` is also what the API-key
  middleware returns for a rotated publishable key, so a key rotation would have
  wiped every install's anonymous account at once.
- **The refresh race, both directions** — gated by `tokenStillCurrent(sent)`.
- **Auth-state listeners are dispatched off the mutex.** `emitAuthState` ran
  inline while `mutex` was held, so a listener calling any suspend auth method
  (`signOut()` from an `onAuthStateChanged` handler) deadlocked permanently.

## 4.13.0 — ApiClient response parsing: two defects that made the whole SDK's nested reads dead

Two independent, PRE-EXISTING transport defects. Neither was introduced by
4.12.0; the taxonomy work simply made the first one impossible to ignore. Both
are fixed at the transport boundary, so every existing call site starts working
without being touched.

**1. A non-2xx response threw its own body away.** `ApiClient.request()` read
the error body and then returned `null`, so every 4xx/5xx reached
`SendoraCloudAuth.parseError` as `Network("Network request failed")` — no
`error.code`, no status, no `error.details.retryAfterSeconds`. The 4.12.0
taxonomy was therefore **inert against the real backend**: `NOT_ANONYMOUS`,
`CONFLICT`, `CREDENTIAL_IN_USE`, `ACCOUNT_LOCKED` and 429 were all unreachable,
and every failure classified as `NETWORK` (retryable) no matter what actually
happened. It also called `recordFailure()` on 4xx, so **a wrong password armed
the circuit breaker** and locked the client out of its own retry. Non-2xx now
returns the parsed body; the breaker is only tripped by a 5xx or a thrown
exception, because it guards the TRANSPORT and a 4xx means the server answered.

**2. Only the TOP level of the envelope was converted to a Map.** `org.json`
returns `JSONObject` / `JSONArray` for nested values, so `data`, `user`,
`tokens`, `error`, `error.details` all stayed `JSONObject`s — and every
`as? Map<String, Any?>` cast against them silently yielded null. The blast
radius is the whole SDK, not just auth: `parseSuccess` could never return a
user (so `callAuth` always failed "Malformed response" and `persist()` never
ran — **Android auth has never worked end-to-end**, consistent with the module
not compiling at all before 4.8.2), plus `parseLinkedUser`, `deleteAccount`,
`listLinkedIdentities` (also `JSONArray` vs `List`), `listMySessions`,
`enrollMfa`/`confirmMfa`, `SendoraCloudPasskeys`' start/finish envelopes, all
four `SendoraCloudLinks` rich paths, deferred-attribution `data.found`, the
geofence list, and the push `tokenId` read. The body is now deep-converted once
(`JSONObject`→`Map`, `JSONArray`→`List`, `JSONObject.NULL`→`null`) in BOTH
`request()` and `doRichRequest()`.

Also: `requestWithDetails`/`doRichRequest` gained the `extraHeaders` parameter
`request()` always had (it could not send a Bearer header, so it was unusable
for any authenticated route), and `parseError` reads the HTTP status that
`withErrorStatus` stamps onto the error envelope — so a failure the backend
gave no `code` for still classifies (5xx→`SERVER`, 429→`RATE_LIMITED`) instead
of collapsing to `UNKNOWN`. `withErrorStatus` deliberately does NOT synthesise
an `error` object when the body carries none: its absence is what makes a
caller fall back to its own default code, and shipped apps string-match those.

**Tests — the module's first.** `src/test/kotlin/.../ApiClientEnvelopeTest.kt`
(10 JVM tests) asserts the exact cast expressions the production parsers use,
against real backend envelope shapes: the login success envelope down to
`data.user.id` / `data.tokens.accessToken`, `retiredAnonUserId` +
`reactivatedFromDeletion`, a JSON `null` arriving as Kotlin null rather than the
`JSONObject.NULL` sentinel, `ACCOUNT_LOCKED` with `error.details.retryAfterSeconds`
+ the stamped status, the `listLinkedIdentities` array-of-objects, a top-level
array (geofences/sessions), deep nesting, and an unparseable body. Wired via a
new `src/test` source set — `testOptions.unitTests.isReturnDefaultValues` plus a
real `org.json:json` on the test classpath, because the mockable `android.jar`
stubs every `org.json` method to throw. **Verified they catch the regression:**
reverting `toDeepMap` to the old shallow form fails 7 of the 10.

`./gradlew testDebugUnitTest` → 10/10, and `./gradlew :publishToMavenLocal`
(JitPack's command) → BUILD SUCCESSFUL. ⚠ A live sign-in against a real project
is still the gate that matters and is operator-owned — these tests prove the
envelope contract, not the network. Additive — no frozen SharedPreferences key /
header / route / wire shape touched (ADR-023), no public signature changed.

## 4.12.0 — a failed sign-in can no longer destroy the account (s58.271)

**The bug (customer-reported, HIGH — silent permanent data loss).** Every
credentialed sign-in cleared local identity — *including the refresh token* —
BEFORE its network call, and no failure path restored it. For an anonymous user
that refresh token is the ONLY durable handle on the account, so once the wipe
landed and the call failed the account was unreachable from the device forever.
Offline it was not a race but a **guarantee**. Word Hurdle lost a real production
account this way on iOS (30 purchases incl. an active subscription, 3,355-gem
balance); Android carried the same defect at **seven** sites — the worst of the
four SDKs: `signIn`, `signInWithMfaSupport`, `loginSocial` (and all seven
`signInWith*` wrappers), `signInWithPlayGames`, `verifyMagicLink`,
`verifyEmailOtp`, and `passkeys.authenticate`, which wiped *before* the
Credential Manager sheet — where cancelling is a routine outcome, not an error.
`signInWithMfaSupport` was worse still: it never read `prevAnonRefreshToken` at
all, so even a **successful** MFA sign-in destroyed the anon refresh without
triggering device-takeover (anon row leaked server-side, `onDeviceTakeover` never
fired). It now forwards the hint exactly like `signIn`.

**The invariant now, everywhere: a failed auth attempt leaves the caller exactly
as it found them.** Each path reads the anon refresh into a local, makes the
call, validates the response, and only then wipes + persists — the shape
`challengeMfa` already used and which was simply never propagated to its
siblings. The shared executor carries it: `callAuth(path, body,
replacesIdentity)` does the wipe itself, between `parseSuccess` and `persist`.
`replacesIdentity` is deliberately FALSE for `/anonymous` and the in-place
`/upgrade` — those keep the same subject, so rotating the device id and dropping
the queued events under them would orphan attribution that legitimately belongs
to the user. The passkey path moved its wipe into the `installSession` lambda
(after `parseSuccess`), so the `wipe` constructor param is gone from
`SendoraCloudPasskeys`. `signOut()` still wipes first — the caller asked to lose
the session. Same fix in RN 1.28.0 / web 3.12.0 / iOS 4.13.0.

Four things ship alongside it:

- **Error taxonomy — `SendoraCloudAuthError.kind` / `.retryable` / `.code` /
  `.status` / `.retryAfterSeconds`.** New `SendoraCloudAuthErrorKind` enum
  (`NETWORK` · `SERVER` · `RATE_LIMITED` · `INVALID_CREDENTIAL` ·
  `ACCOUNT_LOCKED` · `CREDENTIAL_IN_USE` · `ALREADY_IDENTIFIED` · `CANCELLED` ·
  `CONFIG` · `UNKNOWN`) with `SendoraCloudAuthErrorKind.classify(code, status)`
  mirroring the RN classifier 1:1; retryable = network/server/rate_limited/
  account_locked. The error **classes are unchanged** (`when (err) { is
  Unauthorized -> … }` keeps working) and no message string was reworded —
  `Unknown` still reads `"$code: $message"`. `PasskeyError` gains the same `kind`
  so one taxonomy covers every sign-in path (`UserCancelled` → `CANCELLED`).
  `retryAfterSeconds` is read off `error.details` (429 backoff, the new backend
  `ACCOUNT_LOCKED` 403 cool-off).
- **`onAuthStateChanged(listener)`** — one stream (`AuthStateChange.SignedIn` /
  `SignedOut(reason)` / `DeviceTakeover` / `DeletionCancelled`) returning an
  unsubscribe lambda, same UUID-keyed `ConcurrentHashMap` + `runCatching` posture
  as `onDeviceTakeover`, which keeps firing unchanged alongside it. The
  load-bearing case is `AuthSignedOutReason.SESSION_EXPIRED`: a session killed in
  the background (server rejected the stored refresh) previously emitted
  **nothing**, so an app could not tell it from a deliberate sign-out and only
  noticed when `getAccessToken()` returned null. Replays `SignedIn` on subscribe
  once restore has run (never before — reporting "signed out" mid-restore would
  be a lie); a signed-out cold start emits nothing, and a FAILED sign-in emits
  nothing (no state changed). The internal wipe that precedes a successful
  `persist()` is `WipeReason.REPLACED` and emits no `SignedOut`, so one sign-in
  reads as one `SignedIn`, not a logout/login pair.
- **A rate limit is no longer treated as a dead session.** `isDeadRefreshError`
  dropped `RATE_LIMIT`/`RATE_LIMIT_EXCEEDED`: a 429 is transient throttling (a
  shared NAT/CGN egress, a refresh burst) and says nothing about token validity,
  yet it was wiping live sessions from the background refresh path. Kept:
  `INVALID_REFRESH_TOKEN`/`UNAUTHORIZED`/`HTTP_401`. Relatedly the constructor's
  corrupt-cache guard now calls a new `Storage.clearCachedUser()` (user + access
  token) instead of `clearAuthTokens()` — an unreadable `auth_user` blob says
  nothing about the refresh token, which is the only thing that can still recover
  the account.
- **`deleteAccount()` requires a confirmed success before wiping.** It keyed off
  the presence of an `error` object, so a `success:false` body with no error
  slipped through and wiped anyway — account alive server-side, credential gone
  from the device. Now gated on `success == true`.

**⚠ The taxonomy shipped INERT in this version — 4.13.0 is what makes it work.**
Two pre-existing `ApiClient` defects (a non-2xx response discarding its own body,
and only the top level of the envelope being converted to a Map) meant every
backend error reached `parseError` as a bare `Network(...)` and `parseSuccess`
never returned a user at all. `objectField()` here reads either shape wherever
the taxonomy needs the envelope, but the transport itself had to be fixed —
see the 4.13.0 section above. Anything below describing taxonomy behaviour is
only true from **4.13.0** onward.
`./gradlew :publishToMavenLocal` BUILD SUCCESSFUL. Additive — no frozen
SharedPreferences key / header / route / wire shape touched (ADR-023), no error
class or message renamed, no public signature changed.

## 4.11.0 — listLinkedIdentities() (read side of ADR-030, s58.270)

`auth.listLinkedIdentities(): Result<LinkedIdentitiesResult>` (suspend) where
`LinkedIdentitiesResult` = `{ identities: List<LinkedIdentity(provider, email?,
linkedAt)>, hasPassword }`. The full set of credentials on the current account —
the cross-device / reinstall-durable source of truth for a "Connected: Play
Games · Google" UI. Bearer-authenticated GET `/auth-service/me/identities` that
resolves a fresh access token first (mirrors `deleteAccount`; safe under `mutex`
since `getAccessToken` uses a separate `refreshMutex`); `Unauthorized` when
signed out. Firebase `user.providerData` / Supabase `user.identities` parity.
`build.gradle.kts` + `SdkVersion.kt` bumped in lockstep; `./gradlew
:publishToMavenLocal` BUILD SUCCESSFUL. Additive, SDK-only (not in the golden
contract). Parity with RN 1.27.0 / web 3.11.0 / iOS 4.12.0.

## 4.10.0 — onDeletionCancelled (account-restore listener, s58.269)

`auth.onDeletionCancelled(listener)` + `getLastDeletionCancelled()` (returns
`DeletionCancelledEvent`) — mirrors `onDeviceTakeover` (ConcurrentHashMap,
runCatching). Fired centrally from `persist()` when a sign-in cancelled a pending
self-service deletion within grace (account restored, same sub) — reads a new
`reactivatedFromDeletion` boolean off the response. Pairs with backend
`auth.deletion_cancelled`/`auth.deletion_scheduled` webhooks. BUILD SUCCESSFUL.
Additive, not in the golden contract. Parity with RN 1.26.0 / web 3.10.0 / iOS
4.11.0.

## 4.9.0 — identity linking on an identified session (ADR-030) + signUp() fix

Non-anonymous sibling of ADR-025. New `linkEmailPassword` / `linkSocial` (+
`linkGoogle`/`linkApple`) / `linkPlayGames` attach a 2nd credential to an
already-identified account (sub preserved), Bearer-authenticated (mirror
`deleteAccount`'s `getAccessToken` → Bearer POST; safe under `mutex` since
`getAccessToken` uses a separate `refreshMutex`), refresh the cached user in place
via `updateLocalUser` — NO token rotation. The link response carries no tokens, so
a dedicated `parseLinkedUser` (token-less) is used instead of `parseSuccess`.
Collision → new `SendoraCloudAuthError.CredentialInUse`. Game Center is iOS-only,
so Android ships `linkPlayGames` not `linkGameCenter`. **signUp() fix:** a non-anon
`signUp()` used to wipe + fresh-signup (= duplicate account); now returns the new
`AlreadyIdentified` error. `parseError` maps `NOT_ANONYMOUS` → `AlreadyIdentified`
and `CREDENTIAL_IN_USE` → `CredentialInUse`. Compiles (`./gradlew
:publishToMavenLocal` BUILD SUCCESSFUL). Additive, SDK-only (not in the golden
contract). Parity with RN 1.25.0 / web 3.9.0 / iOS 4.10.0.

## 4.8.2 — fix 3 latent Kotlin compile errors (first compiling release)

Once the 4.8.1 wrapper let JitPack reach the compiler, three never-caught compile errors surfaced (the SDK had literally never compiled): `SendoraCloud.kt` missing `import org.json.JSONObject`; a `SendoraCloudLinks.kt` prewarm waiter (non-suspend `(Result)->Unit` invoked via `forEach`) calling suspend `withContext` → switched to `scope.launch(Dispatchers.Main)`; `SendoraCloudLiveActivities.kt` `@SuppressWarnings` (java, not expression-applicable) → Kotlin `@Suppress`. **Verified with a real build** (local Android SDK + `ANDROID_HOME`): `./gradlew :publishToMavenLocal` → BUILD SUCCESSFUL, AAR published, `:compileReleaseKotlin` clean. 4.8.1's tag has a JitPack-cached failed build, so **4.8.2 is the first consumable release**. **CI now compiles this module** — the `Android SDK build` job in `.github/workflows/ci.yml` runs `./gradlew :publishToMavenLocal` (JitPack's exact command) on every PR against the runner's preinstalled Android SDK, so a Kotlin compile error fails CI instead of a JitPack publish. Still smart to build locally (`ANDROID_HOME=… ./gradlew :publishToMavenLocal`) before a mirror push, but the net is no longer open.

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
