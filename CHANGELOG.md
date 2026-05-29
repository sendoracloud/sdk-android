# Changelog

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
