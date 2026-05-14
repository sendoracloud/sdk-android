# SendoraCloud Android SDK

Official SendoraCloud Android SDK — deep linking (Branch / Firebase Dynamic Links parity), attribution, event tracking, auth, push, geofences, live updates. Kotlin 1.9+, minSdk 26.

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
    implementation("com.github.sendoracloud:sdk-android:3.8.0")
}
```

## Quick start

```kotlin
// Application.onCreate
SendoraCloud.init(this, apiKey = "pk_live_...", projectId = "<uuid>")

// Grant consent (GDPR / ePrivacy). Events buffer until this is called.
SendoraCloud.consent.grant()

// Identify with HMAC identity token signed by your backend
SendoraCloud.identify(
    userId = "user_123",
    traits = mapOf("email" to "user@example.com"),
    options = SendoraIdentifyOptions(identityToken = "<HMAC>"),
)

// Track a custom event
SendoraCloud.trackEvent("purchase", mapOf("amount" to 29.99))

// Deep link handling
override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    SendoraCloud.handleDeepLink(intent)?.let { link ->
        // route to link.deepLinkPath
    }
}
```

## Deep links (SDK-side mint + warm + deferred + revoke + stats)

```kotlin
// 1. Mint a share link with prewarm cache so the share tap is instant.
val input = SendoraCloudLinks.LinkCreateInput(
    title = "Share: ${article.title}",
    iosDeepLinkPath = "/articles/${article.id}",
    androidDeepLinkPath = "/articles/${article.id}",
    linkData = mapOf("type" to "article", "articleId" to article.id, "category" to article.category),
    // fallbackUrl: omit — backend defaults from your project's apps registry (web origin > store URL)
)
SendoraCloud.links?.prewarm(input, key = "article:${article.id}")

// On tap — returns from cache when key matches.
SendoraCloud.links?.create(input, prewarmKey = "article:${article.id}") { result ->
    result.onSuccess { link ->
        // share link.url via Intent.ACTION_SEND
    }.onFailure { err ->
        if (err is SendoraCloudLinks.LinkError) when (err.code) {
            SendoraCloudLinks.LinkErrorCode.BUNDLE_MISMATCH    -> /* register package in Dashboard → Apps */ Unit
            SendoraCloudLinks.LinkErrorCode.PLAN_LIMIT         -> /* upgrade plan */ Unit
            SendoraCloudLinks.LinkErrorCode.RATE_LIMITED       -> /* back off + retry */ Unit
            SendoraCloudLinks.LinkErrorCode.FALLBACK_REQUIRED  -> /* configure Play Store URL */ Unit
            else -> Unit
        }
    }
}

// 2. Register the open-callback. Fires for warm + deferred opens.
SendoraCloud.links?.onLinkOpened { event ->
    when (val type = event.linkData["type"] as? String) {
        "article" -> (event.linkData["articleId"] as? String)?.let { navigateToArticle(it) }
        else -> Unit
    }
}

// 3. Warm path — wire from Activity.onCreate / onNewIntent:
intent.data?.let { SendoraCloud.links?.handleAppLink(it) }

// 4. Cold path — call once on first foregrounded launch. Play Install
//    Referrer is the preferred input (100% accurate when present);
//    SDK auto-computes the canonical fingerprint if neither input is supplied.
val client = InstallReferrerClient.newBuilder(this).build()
client.startConnection(object : InstallReferrerStateListener {
    override fun onInstallReferrerSetupFinished(code: Int) {
        if (code == InstallReferrerClient.InstallReferrerResponse.OK) {
            val referrer = client.installReferrer.installReferrer
            SendoraCloud.links?.matchDeferred(
                SendoraCloudLinks.DeferredMatchInput(installReferrer = referrer)
            ) { /* event or null */ }
            client.endConnection()
        }
    }
    override fun onInstallReferrerServiceDisconnected() {}
})

// 5. Revoke + stats (no dashboard scraping).
SendoraCloud.links?.revoke("ab3xk9p") { /* success */ }
SendoraCloud.links?.getStats("ab3xk9p") { result ->
    result.onSuccess { stats ->
        Log.d("links", "${stats.totalClicks} clicks, ${stats.deferredMatches} installs matched")
    }
}
```

### Typed errors

`SendoraCloudLinks.LinkError(code: LinkErrorCode, message, statusCode)`. Codes:

```
BUNDLE_MISMATCH | DATA_TOO_LARGE | EXPIRED | NETWORK | RATE_LIMITED
| NOT_FOUND | UNAUTHORIZED | INVALID_INPUT | PLAN_LIMIT
| FALLBACK_REQUIRED | SERVER | UNKNOWN
```

### Custom share host

Pass `linkHosts` in `SendoraCloudConfig` (default `["go.sendoracloud.com", "sendoracloud.com"]`):

```kotlin
val cfg = SendoraCloudConfig(apiKey = key, linkHosts = listOf("pulse.link"))
SendoraCloud.init(this, apiKey = key, projectId = id, options = cfg)
```

URIs whose host doesn't match are ignored by `handleAppLink` (returns false) — leave your existing router untouched.

### Canonical fingerprint

```kotlin
val hash = SendoraCloudLinks.computeDeviceFingerprint()
// `${platform}|${screenW}x${screenH}|${timezone}|${locale}` → SHA-256 hex.
// Identical recipe across Android / iOS / RN SDKs.
```

Bundle gate: SDK auto-supplies `appContext.packageName` on `links.create()` — backend rejects if it doesn't match a registered Android app for the project.

## Security model

- **Secret-key refusal.** `init()` logs + aborts if given a key starting with `sk_`.
- **HTTPS only.** Ships a library-level `networkSecurityConfig` that disables cleartext traffic. `ApiClient` independently refuses non-https URLs (except localhost / `10.0.2.2` in dev).
- **Identity tokens.** `identify()` accepts an HMAC `identityToken` (signed by your backend) to block client-side spoofing.
- **Host allowlist.** `handleDeepLink` returns `null` for URIs whose host isn't in `config.linkHosts` (default `sendoracloud.com`).
- **Bundle-id gate.** `links.create()` forwards `appContext.packageName` automatically; backend rejects a leaked public key + wrong package as `LinkError(code = BUNDLE_MISMATCH, statusCode = 422)`.
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

Apache-2.0 © SendoraCloud
