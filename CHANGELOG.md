# Changelog

## 4.27.0 — Support: the player's own conversations, verified reporter, ticket context, theming

Parity with RN 1.42.0 (s58.376, asked for by Sudoku Hurdle). Additive; nothing existing changes shape.

- **`SendoraCloud.support.listMyTickets(widgetId)` / `getMyTicket(widgetId, ticketId)` /
  `replyToMyTicket(widgetId, ticketId, body)`** (suspend) — the player's own tickets for a native support screen.
  Refusals throw `SendoraSupportException` (`code`, `status`) — never an empty list.
- **`createTicket(subject, body, …, metadata)`** (suspend) — new on Android; sends the player's access token when
  signed in, so the ticket carries their VERIFIED user id. **`deviceContext()`** — app version + build, OS + version,
  device model, SDK version. `SendoraCloudSupport.sanitizeMetadata(…)` — the backend's rules.
- **`presentContactWidget`** gains `metadata`, `includeDeviceContext` (default true), `attachSession` (default true —
  the token rides the URL fragment), `accent`; **`presentTicketHistory`** gains `accent`. All defaulted and placed
  before `onResult`, so existing calls compile unchanged.
- **Fix:** support calls (incl. `getUnreadCount`) always went to production — they now go through the SDK's configured
  client (`apiBaseUrl`).

## 4.26.3 — README install pin

No code or behaviour change (only `SDK_VERSION`, reported in `X-Sendora-SDK-Version`). The README's Gradle line was
`com.github.sendoracloud:sdk-android:4.0.0`; JitPack versions are exact, so copying it installed 4.0.0. It
now names the current release.

## 4.26.2 — a held guest's refresh must come back for that guest

Parity with RN 1.41.2. Before the server fix (e09c86dc, already live), `/token/refresh` preferred the `sd_rt` refresh cookie over the token in the request body. A phone keeps a native cookie jar, and after a sign-in that jar holds the ACCOUNT's cookie — so refreshing a HELD guest's token was answered for the account, and the SDK wrote the account's token into the guest's slot. The device lost its only copy of the guest's credential; `claimHeldGuest()` / `merge()` then failed with 401 and `restoreHeldGuest()` released the guest. The guest's account was never touched on the server. This SDK's `HttpURLConnection` only sends cookies if the host app installs a default `CookieHandler`, so exposure was app-dependent — but it now applies the same check: a held refresh answered for anyone else fails with `HELD_GUEST_IDENTITY_MISMATCH` and changes nothing. Version bumped in BOTH `build.gradle.kts` + `SdkVersion.kt`.

## 4.26.1 — a dead session is `SESSION_EXPIRED` again; the server's detail moves to `SignedOut.endReason`

**Fix to a 4.26.0 behaviour change (ADR-023: a new value is additive only for a NEW situation).**
A session that died on a server-rejected refresh was reported as `SESSION_EXPIRED` through
4.25.0. 4.26.0 reported the server's own verdict as the reason instead (`REVOKED` / `DELETED`),
which gave two old situations new names: "account deleted on another device" and "sessions
revoked". Adding a value to a union is additive for the compiler, not for a listener that
matched the old value. A listener that acted only on `SESSION_EXPIRED` (the documented pattern, and
the RopoLabs template's session-death handler) silently ignored both, leaving the app on a
signed-in screen where every request fails. Reported by RopoLabs against the published
tarball before any production install.

- `SignedOut.reason` is `SESSION_EXPIRED` for EVERY server-rejected refresh, exactly as 4.25.0.
- New `SignedOut.endReason: String? = null` (wire value: `revoked` / `deleted` / `expired` /
  `reuse` / `unknown`), same shape as `GuestReleased.endReason`. `null` on `USER` /
  `ACCOUNT_DELETED` and from an older backend.
- `REVOKED` / `EVICTED` / `DELETED` stay in `AuthSignedOutReason` so code written against 4.26.0
  compiles; they are never emitted again.
- Nothing else changed (storage, wipe effects, held-slot release rules).

Parity: RN 1.41.1 / web 3.24.1 / iOS 5.4.1. Guard: `AuthMachineConformanceTest`
`refresh_dead.current` (every endReason → `SESSION_EXPIRED` + the exact `endReason`).

## 4.26.0 — sign-in no longer retires the guest — it is held on the device

ADR-033 wave 1, lockstep with RN 1.41.0 / web 3.24.0 / iOS 5.4.0. MINOR (ADR-023):
every existing signature, frozen key and event is kept.

- **Sign-in no longer retires the guest — it is held on the device.** No sign-in
  request carries `prevAnonRefreshToken` / `linkAnonymous` / `onCredentialInUse`
  any more. A replaced guest goes into one of 5 fixed held slots
  (`auth_held_0..4`, EncryptedSharedPreferences) and `AuthStateChange.GuestHeld`
  fires before the one `SignedIn(cause = SIGN_IN)`. New verbs:
  `getHeldGuests()` / `getHeldGuest()` / `restoreHeldGuest(id?)` /
  `discardHeldGuest(id?)` / `claimHeldGuest(id?)` (optional, destructive).
- **`link = true` over an identified session attaches or errors (never switches).**
  `loginSocial(link = true)` / `signInWithPlayGames(link = true)` from a guest or an
  identified account go to `/me/link/*`; already linked → quiet success; owned
  elsewhere → `CredentialInUse`; stale session → kind `RECENT_AUTH_REQUIRED`.
  Typed `link(credential)` / `signInWith(credential)` return `LinkResult` /
  `SignInResult` (`CredentialInUse.switchAccount()` is bound to the refused identity).
- `auth.status()` (`UNKNOWN | SIGNED_OUT | ANONYMOUS | IDENTIFIED | WITHHELD`),
  `authStateReady()`, events `Initial` / `UserUpdated` / `GuestHeld` /
  `GuestReleased` / `SessionWithheld` and `SignedIn.cause`. The legacy `SignedIn`
  replay on subscribe is kept (after `Initial`).
- Opt-in `SendoraCloudConfig.expectedProjectId` (project guard → `WITHHELD`,
  `discardWithheld()`, `PROJECT_MISMATCH`) and `autoRestoreHeldGuest` (default on).
- `deleteAccount(alsoDiscardHeldGuests = false)` — held guests survive by default and
  are never auto-restored afterwards; the result carries `heldGuests`.
- `signUp()` routes by status (guest → `/me/link/email`, signed out → `/signup`,
  identified → `AlreadyIdentified` locally); it never calls `/upgrade`.
- Storage: an `auth_session` record is dual-written beside the four frozen keys
  (frozen keys first); `schema_version` → `2`. A downgrade to 4.25.0 reads a valid
  session; an `auth_session` left behind by a 4.25.0 sign-out is ignored and cleared.
- Fixes: `getAccessToken(forceRefresh = true)` and the proactive anticipation tick
  now really refresh (the lock-side re-check used to hand the distrusted token back).
- `SendoraCloud.reset()` is unchanged (analytics identity only; it never signed the
  auth session out on Android). `reset(includeHeldGuests)` is accepted for parity.
- Deprecated, still callable: `merge(token)` (routes to the held slot), `onDeviceTakeover`
  / `getLastAnonRetirement()` (fire only on a server-reported retirement).

## 4.25.0 — signInAnonymously() no longer replaces a signed-in account

**Behaviour change.** Parity with RN 1.40.0 (reported by RopoLabs on the RN SDK; the
guard here was identical). `signInAnonymously(forceNew = …)` reused an existing *anonymous*
session but fell through when the cached session was an identified account: it minted a
guest and persisted over the account's tokens with no `SignedOut` on `onAuthStateChanged`.
It now returns the current session whatever its kind; `forceNew = true` is the only way to
replace an identified session, and it does so silently. Read `isAnonymous` to know which
you got. The account itself was never at risk server-side. Same fix in web 3.23.0 / iOS
5.3.0. Version bumped in BOTH `build.gradle.kts` + `SdkVersion.kt`.

## 4.21.0 — three methods stopped reporting failure as success

⚠⚠ `ApiClient` is documented "never throws — errors log and the call returns null", so a discarded
response was the only place a refusal could surface. `disableMfa()` is **step-up gated**: a 403
`RECENT_AUTH_REQUIRED`, a timeout, and an open circuit breaker all reported MFA as off while TOTP
stayed enrolled server-side. `revokeSession(id)` / `revokeAllSessions()` back a "sign out this device"
button that reported success on a device that was never signed out.

`revokeSession` and `revokeAllSessions` widen from `Unit` to `Result<Unit>`. ⚠ Kotlin lets a caller
ignore a return value, so this is **source-compatible** — a minor, unlike the same fix on iOS, which
had to break its completion signature.

**New error kind: `SendoraCloudAuthErrorKind.RECENT_AUTH_REQUIRED`.** The credential is valid; the
authentication behind it is too old to authorise a credential change. Not a request for new input:
re-run a sign-in and retry the same call. It previously fell through to `INVALID_CREDENTIAL`.

⚠ Android implements no passkey management, so the gated `DELETE /passkeys/:id` route has no call
site here.

## 4.20.0 — unlink(provider): remove a linked sign-in method

Parity: RN 1.35.0 / web 3.19.0 / iOS 4.20.0 / Android 4.20.0. Additive.

The write half of `listLinkedIdentities()`. An app could already render
"Connected: Google · Game Center"; ``auth.unlink(provider)`` is what the Disconnect
button beside each entry calls.

**⚠ The server refuses to remove the last way into the account** — code
`LAST_CREDENTIAL`, kind ``LAST_CREDENTIAL``. An account with no credentials still
exists and still holds the user's data, but nothing can ever authenticate into
it again: no password to reset, no identity to present. That is permanent
lockout, not an inconvenience, and it is unrecoverable without manual database
surgery. A password counts as a credential, so an account with email+password
plus one social identity may drop the social one.

Supabase enforces the same floor (`unlinkIdentity` requires >= 2 identities);
Firebase's `unlink()` does not and will strip the last provider. We follow
Supabase, deliberately.

**Prefer preventing the tap to explaining the refusal.** Read
`listLinkedIdentities()` and disable Disconnect when
`identities.size + (if (hasPassword) 1 else 0) <= 1`. The error is the backstop, not the UX.

An unlinked provider returns `NOT_FOUND` rather than reporting success — a
screen saying "disconnected" about a credential that is still attached tells
the user something untrue about their account.


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
