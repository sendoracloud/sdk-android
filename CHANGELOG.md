# Changelog

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
