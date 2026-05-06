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

## Publish

Tag a new version; JitPack builds on first consumer request. Gradle wrapper must be committed.
