# Changelog

## 4.19.0 — getAccessToken() no longer returns a token past its own `exp`

Parity: RN 1.34.0 / web 3.18.0 / iOS 4.19.0 / Android 4.19.0. Customer-reported
(Word Hurdle) against the React Native SDK; all four shared the defect.

**Fixed (HIGH — silent, up to a full token TTL).** `getAccessToken()` promises
it never returns a token past its `exp`, but enforced a different value: a
deadline computed as `now + expiresIn` at mint, persisted, restored verbatim.
That deadline is deliberately **skew-invariant** — a permanently wrong clock
cancels on both sides, because it is written in the same frame it is read in —
but blind to a clock that **moves**. Corrected clock after a long power-off, a
restore, or a manual set, and the tracked deadline is stale by exactly the size
of the correction, across relaunches. Observed on a physical device with a token
**1929 seconds past its `exp`**: every request 401'd while the app still looked
signed in.

The token's own `exp` is now required as well. **Requiring it alone would have
been worse than the bug** — a clock fast by more than the token TTL reads every
freshly-minted token as already expired, so every call refreshes, forever
(measured at 10 reads → 10 refreshes). A one-shot probe bounds it: when a
refresh performed *because* the two deadlines disagreed returns a token that
STILL reads expired, the clock is proven fast rather than the deadline stale,
and the guard is released for that process. Never persisted.

Also fixed: the post-lock re-check inside the refresh path applied no `exp`
check, on the one path meant to repair an expired token; and the
proactive-refresh cron reasoned only from the stale deadline, so it never fired
during the window.

**Added — `getAccessToken(forceRefresh = true)`.** The supported way to say "your tracked deadline is wrong".
Skips the cache but not the single-flight or the backoff cooldown, so
force-refreshing on every 401 cannot turn an outage into a hot loop.

`storagePrefix` is deliberately NOT part of this release for Android:
EncryptedSharedPreferences is already scoped per application id, so a debug
variant with an `applicationIdSuffix` is isolated by construction. The React
Native and web SDKs, where one JS bundle can point at two projects, get the
option.


## 4.13.0 — response parsing fixed (auth now works end-to-end)

**Fixed (blocking).** `ApiClient` converted only the top level of a response
body into a Map, leaving `data`, `user`, `tokens` and `error` as
`org.json.JSONObject`s — so every `as? Map` read of them returned null. Sign-in
could never build a user object and always failed with "Malformed response";
the same defect broke `listLinkedIdentities`, `listMySessions`, MFA enrollment,
passkeys, all four Links calls, deferred attribution, the geofence list and the
push `tokenId`. Bodies are now deep-converted (`JSONObject`→`Map`,
`JSONArray`→`List`, JSON null→`null`) once, at the transport boundary.

**Fixed (blocking).** A non-2xx response had its body discarded and returned
`null`, so every backend error surfaced as a generic network failure with no
code, status or `retryAfterSeconds` — making the 4.12.0 error taxonomy inert —
and a wrong password tripped the circuit breaker. The body is now returned, the
HTTP status is stamped onto the error envelope, and only a 5xx or a transport
exception counts as a circuit-breaker failure.

**Added.** `requestWithDetails` accepts `extraHeaders` (it previously could not
send a Bearer header). First unit tests in this module: 10 JVM tests pinning the
envelope contract.

## 4.10.0 — onDeletionCancelled (account-restore signal)

New `auth.onDeletionCancelled(listener)` + `auth.getLastDeletionCancelled()` —
fires when a sign-in **cancelled a pending self-service account deletion** within
its grace window (account restored, same user_id). Mirrors `onDeviceTakeover`;
fired from `persist()` reading a new `reactivatedFromDeletion` flag the backend
now returns on every sign-in response. Show "your deletion was cancelled" +
reconcile local state. Pairs with the server-side `auth.deletion_cancelled` /
`auth.deletion_scheduled` webhooks (s58.269). Compiles (`./gradlew
:publishToMavenLocal` BUILD SUCCESSFUL). Additive, not in the golden contract.

## 4.9.0 — identity linking on an identified session (ADR-030) + signUp() fix

**New: link a SECOND credential to an already-signed-in account, preserving the
sub** — the cross-platform account-unification primitive. `auth.linkEmailPassword`,
`auth.linkSocial` (+ `auth.linkGoogle` / `auth.linkApple`), `auth.linkPlayGames`.
All require a signed-in session (Bearer), preserve the sub, do NOT rotate tokens,
and refresh the cached user in place. Collision (the credential already belongs to
another account) → new `SendoraCloudAuthError.CredentialInUse` (never merges). Use
to make one account reachable across platforms (a Play Games player on Android
links email/Google, then signs in on iOS to the SAME sub).

**Fix: `signUp()` on an already-identified session** now returns the new
`SendoraCloudAuthError.AlreadyIdentified` instead of silently wiping the session +
minting a duplicate account. `parseError` also maps the backend's new
`NOT_ANONYMOUS` code → `AlreadyIdentified` and `CREDENTIAL_IN_USE` →
`CredentialInUse`.

Additive, SDK-only (not in the golden wire contract); no frozen key/header touched.
Parity with RN 1.25.0 / web 3.9.0 / iOS 4.10.0.

## 4.8.2 — fix 3 pre-existing Kotlin compile errors (first compiling release)

With the wrapper landed (4.8.1) JitPack finally reached the Kotlin compiler and
surfaced **three latent compile errors** — present since the code was written but
never caught, because the SDK had never once compiled (JitPack died at the missing
`gradlew`, and the monorepo has no Android SDK). Fixed:

- `SendoraCloud.kt` — missing `import org.json.JSONObject` (used at the traits
  size-cap). Added the import.
- `SendoraCloudLinks.kt` — a prewarm *waiter* lambda (`(Result) -> Unit`, a
  non-suspend type invoked via `forEach`) called the suspend `withContext` →
  "Suspension functions can be called only within coroutine body". Now hops to
  Main with a non-suspend `scope.launch(Dispatchers.Main) { … }`.
- `SendoraCloudLiveActivities.kt` — `@SuppressWarnings("MissingPermission")`
  (java.lang, not applicable to a Kotlin expression) → Kotlin `@Suppress(…)`.

**Verified with a REAL build** (local Android SDK, `ANDROID_HOME` set):
`./gradlew :publishToMavenLocal` → BUILD SUCCESSFUL, 27 tasks,
`:compileReleaseKotlin` clean (4 benign warnings), AAR published to mavenLocal.
This is JitPack's exact command. 4.8.1's mirror tag has a JitPack-cached *failed*
build, so **4.8.2 is the first release that actually builds + is consumable** via
`com.github.sendoracloud:sdk-android:4.8.2`. Still carries the s58.266 method
fields. No behaviour change beyond making the code compile.

## 4.8.1 — fix JitPack build (commit the Gradle wrapper + settings)

**Every prior version (≤4.8.0) failed to build on JitPack** with `./gradlew: No
such file or directory` (exit 127): the package had `jitpack.yml`
(`./gradlew :publishToMavenLocal`) + `build.gradle.kts` but was **missing the
Gradle wrapper, `settings.gradle.kts`, and `gradle.properties`** — so JitPack had
no `gradlew` to invoke, and even with one the `com.android.library` plugin had no
version/repository to resolve from. This commits:

- `gradlew` / `gradlew.bat` / `gradle/wrapper/gradle-wrapper.{jar,properties}` —
  the canonical Gradle **8.2** wrapper (jar sha256 `a8451ee…46e4`, from
  gradle/gradle@v8.2.0).
- `settings.gradle.kts` — `pluginManagement` pins **AGP 8.2.2** + **Kotlin
  1.9.22** (google/mavenCentral/gradlePluginPortal) + `dependencyResolutionManagement`.
- `gradle.properties` — `android.useAndroidX=true` (required by the androidx.*
  deps).

Verified locally: `./gradlew projects` → BUILD SUCCESSFUL (wrapper + settings +
AGP + Kotlin all resolve, `build.gradle.kts` evaluates), and
`./gradlew :publishToMavenLocal --dry-run` reaches the AGP task graph and stops
only at "SDK location not found" — the one thing JitPack's build servers supply.
No SDK behaviour change; source-identical to 4.8.0 (which already carries
`AuthUser.signupMethod`/`.lastLoginMethod`). 4.8.0's mirror tag is left as-is
(un-buildable); **4.8.1 is the first buildable release with the method fields.**

## 4.1.0

**Wave 51 — Play Install Referrer.**

`reportInstallIfNeeded` now consults Google Play's `InstallReferrerClient` on first launch and routes the install through the new `/attribution/install-referrer` endpoint when a referrer is available. Server-side deterministic match on `sendora_link_id` / `gclid` / `fbclid` / `ttclid` / `utm_source+utm_campaign` runs **before** fingerprint/IP fallback, surviving Play Store handoff.

**Host app must add the dep** for install-referrer support:

```kotlin
dependencies {
    implementation("com.android.installreferrer:installreferrer:2.2")
}
```

SDK declares the dep `compileOnly`, so apps without it skip the referrer path and fall back to `/attribution/install` (unchanged behaviour).

## 4.0.5

**Device-takeover inline listener** (parity with RN 1.0.5).

New API on `SendoraCloud.auth`:

```kotlin
val unsub = SendoraCloud.auth?.onDeviceTakeover { evt ->
    // evt.retiredAnonUserId — the anon user_id Sendora hard-deleted
    // evt.identifiedUserId  — the identified user_id that took over
    // evt.at                — epoch ms when the SDK observed the event
    // Delete the matching row from your local users mirror so
    // audience queries joining on user_id stop matching the stale
    // anon row.
}

val last = SendoraCloud.auth?.getLastDeviceTakeover()
```

Fires on every identified-signin path when the backend retired an anon
row during the request: `signIn`, `loginSocial` / `signInWithGoogle` /
`signInWithGitHub` / `signInWithApple` / `signInWithMicrosoft` /
`signInWithLinkedIn` / `signInWithFacebook` / `signInWithDiscord`,
`verifyMagicLink`, `verifyEmailOtp`, `challengeMfa`, passkey
authenticate.

Local-only — survives webhook receiver downtime. For server-pipeline
cleanup also subscribe to the `auth.device_takeover` webhook.

See `/docs/device-takeover` on sendoracloud.com for the full
architecture writeup.

## 4.0.4

Device-takeover plumbing: every identified-signin path forwards the
anon refresh token to the backend as `prevAnonRefreshToken` so the
anon `user_id` is retired + push tokens reassigned to the
identified user. Inline listener API added in 4.0.5.

## 4.0.0

**Major bump** to align with backend s58.104 unprefixed alias routes.

- Backend resolves `orgId` from the API key server-side. No SDK-side
  `orgId` parameter exists (and never did on Android) — nothing to change
  in your `SendoraCloud.init(context, apiKey, projectId, options)` call.
- Internal URL construction was already unprefixed
  (`/api/v1/<path>` via `ApiClient`), so this release is API-compatible
  in source.
- Bundled SDK `version` string used in event `context.sdk.version` bumped
  to `4.0.0`.

### Migration

```diff
- implementation("com.github.sendoracloud:sdk-android:3.8.0")
+ implementation("com.github.sendoracloud:sdk-android:4.0.0")
```

No code changes required. All public method signatures (`init`,
`trackEvent`, `identify`, `handleDeepLink`, `auth.*`, `push.*`,
`liveActivities.*`, `geofences.*`, `passkeys.*`, …) are unchanged.

## 3.8.0 and earlier

See git tags at https://github.com/sendoracloud/sdk-android/tags
