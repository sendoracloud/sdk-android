# Sendora Android SDK

Official Sendora Android SDK — deep linking, attribution, event tracking. Kotlin, minSdk 26.

Full docs: [sendoracloud.com/sdks](https://sendoracloud.com/sdks)

## Install (via JitPack)

Add the JitPack repo to your root `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

Add the dependency in your module's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.sendoracloud:sdk-android:1.0.0")
}
```

## Quick start

```kotlin
// Application.onCreate
Sendora.init(this, apiKey = "pk_live_...", projectId = "<uuid>")

// Grant consent (GDPR / ePrivacy). Events buffer until this is called.
Sendora.consent.grant()

// Identify with HMAC identity token signed by your backend
Sendora.identify(
    userId = "user_123",
    traits = mapOf("email" to "user@example.com"),
    options = SendoraIdentifyOptions(identityToken = "<HMAC>"),
)

// Track a custom event
Sendora.trackEvent("purchase", mapOf("amount" to 29.99))

// Deep link handling
override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    Sendora.handleDeepLink(intent)?.let { link ->
        // route to link.deepLinkPath
    }
}
```

## Security model

- **Secret-key refusal.** `init()` logs + aborts if given a key starting with `sk_`.
- **HTTPS only.** Ships a library-level `networkSecurityConfig` that disables cleartext traffic. `ApiClient` independently refuses non-https URLs (except localhost / `10.0.2.2` in dev).
- **Identity tokens.** `identify()` accepts an HMAC `identityToken` (signed by your backend) to block client-side spoofing.
- **Host allowlist.** `handleDeepLink` returns `null` for URIs whose host isn't in `config.linkHosts` (default `sendoracloud.com`).
- **Encrypted storage.** `userId` + `deviceId` live in `EncryptedSharedPreferences` (AES256-GCM, master key in AndroidKeyStore). Event queue persisted to disk has `userId` + `traits` stripped.
- **Backup exclusion.** Ships `sendora_backup_rules.xml` — opt into it in your manifest to exclude the SDK's prefs from Auto Backup.
- **Input validation.** Event names must match `[A-Za-z0-9._:-]{1,128}`; properties cap at 32 KB, depth 5; `__proto__`/`constructor`/`prototype` keys are blocked.
- **Consent gating.** Events buffer in-memory until `consent.grant()`.
- **Exponential backoff + circuit breaker.** `ApiClient` backs off to 60 s after repeated failures and drops after 10 — no retry storms against your API.
- **CSPRNG IDs.** `UUID.randomUUID` (backed by `SecureRandom`).

## Backup rules (recommended)

Merge the included rules with your own:

```xml
<!-- AndroidManifest.xml -->
<application
    android:fullBackupContent="@xml/sendora_backup_rules"
    tools:replace="android:fullBackupContent">
```

## License

Apache-2.0 © Sendora
