# sdk-android

Published at `github.com/sendoracloud/sdk-android`, consumed via JitPack (`com.github.sendoracloud:sdk-android:<version>`; the current version shown to integrators is `SDK_RELEASES.android` in `packages/shared/src/constants/sdk-releases.ts`). Kotlin 1.9+, minSdk 26.

> ⚠ **ADR-023 frozen contract.** SharedPreferences keys (`auth_*`, `event_queue`, `device_id`, `session_id`, …), the `X-Sendora-SDK-{Name,Version}` headers, and the `schema_version` marker are depended on by installed apps — never rename/remove a key (orphans session/queue on upgrade) or drop the header/marker. Version lives ONLY in `SdkVersion.kt` (must equal `build.gradle.kts`). Additive only; a format change is MAJOR + needs a migration. CI cap: `apps/backend/src/modules/developer-tools/sdk-contract-golden.test.ts`. Law: `docs/decisions/023-sdk-api-compatibility.md`.



## ⚠ Dependency locking — `gradle.lockfile` (s58.346)

`build.gradle.kts` enables `dependencyLocking { lockAllConfigurations() }` and a
committed `gradle.lockfile` pins every resolved transitive version. Reason: it's
the ONLY artifact `osv-scanner` can read to CVE-scan the Android deps (it can't
resolve versions from `build.gradle.kts` alone). First scan (s58.346): 100
packages, **0 issues**.

⚠ **Regenerate on ANY dependency change**, or the build fails against the stale
lock (that failure is the point — it forces a conscious re-lock):

```bash
ANDROID_HOME=~/Library/Android/sdk ./gradlew dependencies --write-locks --no-daemon
```

⚠ **The lockfile is enforced on the JitPack path too** — the mirror sync carries
it (it's at the module root, not under `build/`), so `:publishToMavenLocal` (what
JitPack runs) validates against it. Safe because every direct version is
exact-pinned → deterministic resolution from google()/mavenCentral() under the
committed 8.2 wrapper. Verified both `testDebugUnitTest` and `:publishToMavenLocal`
green with the lock active before it landed. If a dep bump ever makes JitPack
resolve a different transitive, re-lock locally first and commit the new lockfile.

## ⚠ The version lives in TWO files — keep them in lockstep

`build.gradle.kts` (`version = "..."`) **and**
`src/main/kotlin/com/sendoracloud/sdk/internal/SdkVersion.kt` (`SDK_VERSION`).

Bumping only one is silent at compile time and only surfaces at publish, where
`scripts/publish.mjs android` refuses with "version mismatch across source
files". That guard is the only thing standing between a release and an SDK that
announces the OLD version in its `X-Sendora-SDK-Version` header while published
under the new one — which corrupts every version-correlated support question
without ever failing a build. It caught exactly this on the 4.18.0 bump.



## 4.30.0 (s58.405) — built, not published

`Storage.saveEventQueue` keeps `userId` / `properties.traits` (same drop as iOS) and strips `identityToken` (trackEvent stamps it at enqueue — it WAS written to plain prefs); `validateProperties` counts UTF-8 bytes (it counted chars; a behaviour change for 32 KB+ multi-byte properties); key error says 19+ chars. Guards `PersistedQueueIdentityTest` (3) + `ValidatorBytesTest` (3; ⚠ JVM org.json escapes U+2000–20FF like "€" as `\u20ac`, Android does not — byte tests use "中"); 147 JVM tests (8 live skipped).

## 4.29.0 — server consent + feature flags, identify()'s identityToken (s58.404)

**What.** `SendoraCloudServerApis.kt`: `withInputIdentityToken` (pure port of RN `withInputIdentityToken`, RN ≥ 1.43.0),
`callServer` (2xx → `data`; refusal → `SendoraCloudApiException(operation, status, code)`; null answer → status 0
`NETWORK`; no transport → `NOT_CONFIGURED` — never a silent null), typed results `ConsentRecordResult` /
`DeletionRequestResult` / `FlagValue`, and `SendoraCloudFlags` (`SendoraCloud.flags`). `SendoraCloudConsent` gained
`record` / `requestDeletion`; the local `grant()` / `revoke()` / `isGranted` gate is byte-for-byte the old behaviour.
Seams (`transportProvider`, `userIdProvider`, `proofProvider`) default to the singleton, so the JVM suite drives them.
**Token rule:** explicit argument wins; else identify()'s token only when the call's userId equals the userId identify()
was given WITH that token (`identityTokenUserId` — not `currentUserId`, which a sign-in also rewrites), within the route's
limit (flags ≤ 128, consent ≤ 256 — the zod `.max`). Flags' userId defaults to the identified user (`currentUserId`);
consent's does NOT (RN parity: a consent call names its user or no one). In memory only; cleared by `reset()`, the
auth wipe and an `identify()` without a token. Bodies are built key-by-key, never a null value.
**Response shapes (read from the routes):** `/feature-flags/evaluate` → `{ key, value, ruleMatched }`;
`/feature-flags/evaluate-all` → an ARRAY of those (keyed here by `key`; a map is tolerated). ⚠ RN's TypeScript types
declare `{ value, variant, reason }` and a Record — neither field exists on the wire today; Android reads `ruleMatched`
into `reason` and leaves `variant` null rather than invent it.
**Guards.** `ServerApisTest` (8 — the rule through the REAL `identify()` / `reset()` with `isConfigured` set by
reflection, no-null bodies, decoding, typed errors), `WireSchemaContractTest` +3 (bodies vs `recordConsentSchema`,
`createDeletionRequestSchema`, `evaluateFlagSchema`, `evaluateAllFlagsSchema` read from `packages/shared/src/types`).
Live **T8** (`LiveStagingTest.s8_…`): all four calls 2xx on staging; token present for the identified user's record +
evaluate, absent for another user's deletion request + evaluateAll (a well-formed unprovable HMAC: the server answers
2xx, unverified). Mutations X1–X12, all red (explicit wins 4, any-user 1, no limit 1, reset keeps 1, tokenless identify
keeps 1, null in body 1, no userId default 1, refusal swallowed 1, array not decoded 1, ruleMatched ignored 1, wire key
renamed 2, flag limit 256 1). README section added (snippet gate green).

**4.29.0 consumer-test fixes (s58.404, found on a real emulator — none is visible to a JVM test).** A scratch app
depending on the mavenLocal AAR, run on `Pixel_3a_API_34` against staging, found three pre-existing defects:
- **R8.** `compileOnly` installreferrer + play-services-location → AGP 8 R8 "Missing class" ERROR in every minified app
  without them. `consumer-rules.pro`: `-dontwarn` both + `-keepnames` the two probed classes (so `Class.forName`
  survives obfuscation when the app has them). `SendoraCloudGeofences.isLocationAvailable(op)` (probed once) guards
  `refresh` / `stop` / `handleBroadcast` (all threw `NoClassDefFoundError`; `refresh` from a scope with NO exception
  handler → app crash) and the scope got a handler. Proven: the consumer's minified build passes with NO app-side
  `-dontwarn`; geofence calls on-device are no-ops. Guard `GeofenceOptionalDepTest` (the lib is absent from the test
  runtime classpath, like an app without it).
- **Backup restore.** `EncryptedSharedPreferences.create` on a restored `sendora_sdk_secure.xml` throws
  `AEADBadTagException` (cause keystore2 `VERIFICATION_FAILED`) every launch → `securePrefs` null forever → every
  sign-in `SecureStorageUnavailable`, an ephemeral device id per launch. `openSecureStoreWithRecovery` (Storage.kt):
  content failures only (`isUnreadableSecureStore`: `BadPaddingException` / `*InvalidProtocolBufferException` anywhere in
  the cause chain) → `deleteSharedPreferences` + recreate ONCE, logged; anything else / a second failure stays
  fail-closed. ⚠ The master key alias is deliberately NOT deleted — `_androidx_security_master_key_` is the library
  DEFAULT alias, shared with the host app's own encrypted prefs. `Storage` now has an internal primary constructor
  `(prefs, securePrefs)` so the suite drives the real class over `MemoryPrefs`. Emulator: restored copy → recovery
  logged, fresh guest, same user + device id over 2 relaunches. New `res/xml/sendora_data_extraction_rules.xml`
  (Android 12+ ignores `fullBackupContent` for targetSdk 31+ apps); README section rewritten.
- **Foreground process death.** The queue reached disk only on `onStop` / after a flush answer. `EventQueue.add` now
  arms ONE coalesced write `PERSIST_COALESCE_MS` (1 s) later on the queue's IO scope (`schedulePersistLocked`);
  `track()` only launches the add, so it never waits. Emulator: 7 events queued (consent pending), force-stop 1.5 s later
  → "Loaded 7 persisted events" → delivered 201 on relaunch. ⚠ The last ≤ 1 s is still lost by design.
- Guards: `SecureStoreRecoveryTest` (5), `EventQueueTest` +2, `GeofenceOptionalDepTest` (1) — 141 JVM tests (8 live
  skipped). Mutations S1–S5, Q1–Q3, G1, all red (table below). Live suite re-run after: 8/8 PASS.

## 4.28.0 — F67: queue chunks + permanent-4xx drop, Retry-After / cf-mitigated, knownDeviceToken, push Bearer, final link revoke (s58.402)

**Why.** Two shipped queue defects made an offline backlog permanent: `EventQueue` sent the WHOLE queue (≤ 1000) as ONE
`/events/batch` (backend `batchEventsSchema.max(100)`) → a 400 on every flush once > 100 queued; and a permanent 4xx
kept the chunk at the head forever. Plus the backend's F67 contract (every 429/503 carries `Retry-After` + the same
`error.details.retryAfterSeconds`; Cloudflare may answer `cf-mitigated: challenge` with 403/503) and the server halves
of F23 (`knownDeviceToken`), F53 (push binding by Bearer), F34 (link `revokeToken`).

**What.**
- `internal/EventQueue.kt`: chunks of ≤ `MAX_BATCH` (100), oldest first, removal by entry IDENTITY (mid-flight adds and
  overflow trims can no longer shift what a flush removes). `classifyFlush` (pure): cf-mitigated → RETRY (checked
  FIRST, a 403 challenge is never a DROP); 2xx ACCEPTED; 0 RETRY_UNANSWERED; 400/401/403/404/413/422 DROP; everything
  else (408/429/5xx/402/409…) RETRY. RETRY counts one attempt per sent event, dropped at `MAX_ATTEMPTS` (50);
  UNANSWERED (offline) spends NO budget. Backoff = `Backoff.delayMs` (full jitter random(0, min(60 s, 2ⁿ s)), floor
  `Retry-After` capped 1 h, cf ≥ 60 s); no flush starts before it. Handler returns `FlushResult` (`Deferred` for
  consent-pending: no attempt, no backoff). Attempt counts persist under the ADDITIVE plain key `event_queue_attempts`
  (parallel JSON int array — never inside an event, which is sent verbatim); a length mismatch = all zeros.
  Seam: `EventQueueStore` (Storage implements it).
- `internal/ApiClient.kt`: one `exchange()` feeds both response shapes; reads `Retry-After` (seconds or HTTP-date) +
  `cf-mitigated`. Breaker: 503 / cf → failure with the server floor; other 5xx / I/O → failure, full jitter; **429 →
  a hold of min(Retry-After, 60 s), count untouched**; any other 4xx → never trips. Envelope path: cf → `null`
  (offline — so no auth path can read a challenge as a dead credential or wipe a session); a header-only wait is
  stamped into `error.details.retryAfterSeconds`. Rich path: `RichResponse.retryAfterSeconds` / `cfMitigated`
  (code `CF_CHALLENGE`); a breaker refusal reports the time left. Also fixed: a bodiless 4xx (null `errorStream`) threw
  and armed the breaker. Seams: `clock`, `random`, `RichTransport`.
- `knownDeviceToken`: `AuthKeys.KNOWN_DEVICE_TOKENS` (`auth_known_devices`, secure tier, in the NEW
  `DEVICE_SECRET_KEYS`, deliberately NOT `SECURE_KEYS`/`SLOT_KEYS` — the conformance equality stays true and signOut
  keeps it). `{k: sha256(trim+lowercase(ROOT) email), t, at}`, newest 20 (`internal/KnownDeviceTokens.kt`). Saved from
  `/login` + `/mfa/challenge` successes in `performSwitch` (the ONE funnel every password / ADOPT / MFA sign-in uses)
  via `commit(AuthTx.KnownDevice)`; MFA files it under the email that started the challenge (in-memory, ≤ 8). Sent on
  every `/login` body. ⚠ Lifetime (same rule on all four SDKs, review M5): survives `signOut()` AND
  `SendoraCloud.reset()` / `resetSession` (apps reset at logout); ONLY `deleteAccount()` removes an entry — the deleted
  account's (`AuthTx.ForgetKnownDevice(email)`, captured before the Clear). Never logged; tokens > 2048 ignored.
- **Review fixes (adversarial pass).** (H1) chunks are also bounded to `MAX_BATCH_BYTES` = 60 000 serialized UTF-8
  bytes (`/events/batch` 413s a body > 64 KB; one event may carry 32 KB) — size cached per entry, an oversized event
  goes alone. (M1) 400 / 413 / 422 on a MULTI-event chunk → `BISECT`: halve and resend (no removal, attempt or
  backoff); a single event still refused DROPs; after an accepted half the limit doubles back (round 3: a dropped
  culprit no longer resets it — see below). 401 `IDENTITY_UNVERIFIED` → RETRY (`FlushResult.Sent.errorCode`). `trackScreen` refuses names
  > 128. (M2) ⚠⚠ Android's built-in `org.json` writes a null map value as JSON `null` and the schema's `.optional()`
  fields reject it — `projectId: null` failed EVERY batch of an app initialised without one, and the new permanent-4xx
  rule would have dropped them all. The JVM's org.json 20231013 OMITS nulls, so no JSON-level JVM test can see it:
  `buildEventPayload` (pure) writes a key only when non-null, the queue `compactEvent`s every entry (top level + nested
  maps, NOT inside `properties`; also strips `JSONObject.NULL` from a persisted 4.27.0 queue), and the install /
  deferred bodies dropped their `projectId to null`. Tests assert on the MAP. (LOW) `Backoff.serverFloorMs` caps the
  seconds BEFORE `* 1000` (overflow went negative → wait ignored).
- **Per-event identity refusals in a 2xx (backend s58.402).** `data.rejected[i] = {index, reason, code}`:
  rows with `code == "IDENTITY_UNVERIFIED"` (or, with NO code, a `reason` containing "identity", any case) are KEPT,
  spend one attempt and back off, and the pass stops (they sit at the head); every other row is removed with the
  accepted events, by identity (`identityRejectedIndices` + `FlushResult.Sent.identityRejected`, parity RN). A
  whole-chunk `401 IDENTITY_UNVERIFIED` only when identity refused every event; a mixed refusal is `422
  EVENTS_REJECTED` → bisection. ⚠ The `flushEvents` wiring in `SendoraCloud.kt` needs a Context, so it is not JVM-tested.
- **Round 3 (second adversarial review; same rules on all four SDKs).** (1) An edge challenge, a 429 and Cloudflare
  520–527 / 530 are RETRY_UNANSWERED — they back off (server wait / 60 s floor honoured) but spend NO budget. (2) The
  identity token is attached at SEND time by `decorate` = `decorateWithIdentity(event, currentUserId,
  currentIdentityToken)` (only when the event's `userId` IS the identified user; replaces a stale stamp; never stored);
  the decorated size is what the 60 000-byte cap counts. (3) The chunk cap is a queue FIELD: a BISECT halves it and it
  stays halved — across passes and through a dropped lone event — until a SUCCESS doubles it back; one flush makes at
  most `MAX_POSTS_PER_FLUSH` = 20 POSTs, then (if the pass bisected / dropped) waits the normal backoff. (4) Three
  answered 5xx in a row on the SAME multi-event chunk (same head entry, same size) halve the cap; a lone event spends
  its 50 attempts. (5) Every queued event goes to `/events/batch` — `/events` caps a body at 32 KB, so a lone 32–60 KB
  event 413'd and dropped (`flushEvents` is `internal` now so the suite drives it against a real socket).
- `SendoraCloudPush.registerToken`: `Authorization: Bearer <auth.getAccessToken()>` when a session exists; a null /
  throwing provider registers exactly as before (the server treats a bad Bearer as unproven, not an error).
- Links: `LinkCreateResult.revokeToken: String? = null` + the 4.27.0 7-arg secondary constructor (binary-compatible;
  ⚠ `copy()` gained a parameter — a binary caller of the old `copy` would break; acceptable for a result type);
  `toString` redacts it. Kept per shortcode in plain prefs `link_revoke_tokens` (newest 200, `PlainStore` seam).
  New `revoke(shortcode, revokeToken: String?) { Result<LinkRevokeResult(shortcode, final)> }` (explicit token wins,
  else the kept one; forgotten on success; wrong token → 403 UNAUTHORIZED, kept). The 4.27.0
  `revoke(shortcode) { Result<Unit> }` delegates (so it now presents the kept token → FINAL). cf → `NETWORK`.

**Guards (JVM, 62 new; 112 total).** `EventQueueTest` (31), `EventPayloadTest` (4), `ApiClientRetryTest` (9, real `HttpURLConnection` against
`TestHttpResponder`, a raw-socket server — android.jar has no `com.sun.net.httpserver`), `KnownDeviceAndEdgeTest` (8,
incl. a real ApiClient refresh / sign-in against a cf 403 whose body even says `INVALID_REFRESH_TOKEN`),
`PushAndLinksTest` (10).

**LIVE run against STAGING (`LiveStagingTest`, s58.402).** SKIPPED unless `SENDORA_LIVE=1`; key = `SENDORA_PK` from
`.env.e2e.local` (must be `pk_dev_`; `pk_prod_` / `pk_live_` refused; base URL is a constant
`https://api-dev.sendoracloud.com`, never an input; the key/tokens are never printed — evidence lines only). Run:
`set -a; . ./.env.e2e.local; set +a; SENDORA_LIVE=1 ./gradlew testDebugUnitTest --tests '*LiveStagingTest*' --rerun
--no-daemon` (`--rerun`: env is not a task input, a cached pass would replay). Drives `buildEventPayload` → the real
`EventQueue` → the same send `flushEvents` makes; `SendoraCloudAuth` / `SendoraCloudLinks` / `SendoraCloudPush` over the
real `ApiClient`. First run (2026-10-18), all PASS: 250 events → 100/100/50 (≤ 38.6 KB, 201 ×3, count 250, no nulls) and
a raw `projectId:null` → **422** (the M2 proof); 12 × 8 KB → 7 + 5 (57.9 KB / 41.4 KB); one schema-bad event (eventType
200 chars) among 10 good → 422 bisected 11→6→3→1 and dropped, a 70 KB event → 413 alone and dropped, 10 accepted, 9
POSTs in one flush; real 429 (lane exhausted with 224 raw requests) → Retry-After 1 s, the queue waited 1.2 s, 0
attempts spent, delivered on the next POST; guest → signUp → signIn#1 (no kdt sent, staging returned one, stored under
sha256(email), no raw email on disk) → signIn#2 sent it → resetSession kept it → deleteAccount (`purged`) removed it;
push `/push/tokens` 2xx with `Authorization: Bearer`; link mint `lrt_…` kept → revoke body `{revokeToken}` → `final:
true`, forgotten. ⚠ Not live-testable here: the `SendoraCloud.init` wiring itself (needs a Context), Android's own
`org.json` null behaviour (JVM omits nulls — the raw-null request stands in), `cf-mitigated` (staging is nginx, no CF
challenge), 503/52x and MFA.

**T4 (real 429) must be deterministic (s58.403).** The staging ingest lane refills ~3 a second, so one SDK POST could
slip between raw requests and get a 201 — the 4.28.1 release gate failed that way. The harness keeps eight background
threads posting raw (no SDK code) and only then hands the SDK events, re-flushing ≤ 20 times until one of ITS OWN POSTs
is refused 429; a missing backoff timestamp prints "n/a" rather than a negative wait.

**⚠⚠ The B9 publish gate now drives THIS SDK (`LiveLifecycleTest` + `LiveStagingTest`, contract 2 of
`scripts/e2e/live-run-contract.mjs`).** The old marker came from the WEB SDK whatever `--sdk` said — Android 4.26–4.28
"passed" without one line of Kotlin meeting a server. `LiveLifecycleTest` ports `scripts/e2e/auth-lifecycle.mts` step for
step (A1–A7, B1–B5, W1-a/b/c/d/g/g2/e, B8, B9) over the real `SendoraCloudAuth` / `ApiClient`, with a `CookieManager`
installed as the default `CookieHandler` (a phone's jar — s58.360) and `RecordingStore` as the disk (one instance = one
device: the cold start and the withheld hydrate are real). Play Games stands in for Game Center in W1-g (iOS-only);
W1-e's "anonymous_id kept" is not portable (Android's device id lives in the Context-backed `Storage`). Both suites write
`SENDORA_LIVE_RESULT` after every step through `LiveReport` (`LiveSupport.kt`): merged by step id under the same nonce,
so suite order does not matter; `sdkReportedVersion` read by reflection off `SdkVersionKt`; details scrubbed of
emails / JWTs / keys / `kdt1.` / `lrt_`. `LiveEnv` refuses any host but `api-dev.sendoracloud.com` and any
`pk_prod_` / `pk_live_` / `sk_prod_` / `sk_live_` credential. `build.gradle.kts` forwards the `SENDORA_*` env to the test
JVM and marks a live run never up-to-date. Run:
`set -a; . ./.env.e2e.local; set +a; SENDORA_LIVE=1 SENDORA_API=https://api-dev.sendoracloud.com SENDORA_LIVE_NONCE=…
SENDORA_LIVE_RESULT=… ./gradlew testDebugUnitTest --tests '*Live*' --rerun --no-daemon -q`. First full run
(2026-10-19): `judgeLiveRun` ok — 28 / 28 required steps pass, none exempt.
⚠⚠ **It found a real bug on its first run: `claimHeldGuest()` / `merge()` had NEVER worked on Android.** `POST
/auth-service/merge` sent `{ anonRefreshToken, refreshToken }`; `authMergeSchema` is `{ anonymousRefreshToken,
targetRefreshToken }` → 400 VALIDATION_ERROR on every claim. Two unit suites asserted the wrong names (a test that
restates the wire contract only proves the SDK agrees with itself). Fixed; `WireSchemaContractTest` now reads the keys
out of `packages/shared/src/types/auth-service.ts` and compares the SENT body (merge + guest discard). Mutation S1
(revert the names) → 3 red. ⚠ The raw `projectId: null` probe in T1 is evidence only: staging refused it (422) on
10-18 and accepts it (201) on 10-19 — the server was made tolerant; the SDK's own guard is the no-null-in-the-map check.

**Mutation record** (cp backup → mutate → `testDebugUnitTest` → cp restore, `filecmp` byte-identical each time):

| # | mutation | red |
|---|---|---|
| M1 | whole queue as one batch | 9 |
| M2 | permanent 4xx kept (no DROP) | 8 |
| M4 | no attempt cap | 1 |
| M5 | offline spends the budget | 2 |
| M6 | backoff gate ignored | 2 |
| M7 | Retry-After ignored | 9 |
| M8 | server wait uncapped | 2 |
| M9 | no 60 s edge floor | 2 |
| M10 | fixed doubling, not full jitter | 2 |
| M11 | 429 holds nothing | 2 |
| M12 | 429 hold unclamped | 1 |
| M13 | 503 ignores Retry-After | 1 |
| M14 | cf challenge returned as a refusal | 2 |
| M15 | plain 4xx trips the breaker | 2 |
| M16 | null errorStream read (bodiless 4xx) | 1 |
| M17 | header-only Retry-After not stamped | 1 |
| M18 | kdt not sent on /login | 4 |
| M19 | kdt cleared by signOut | 4 |
| M21 | MFA email not remembered | 1 (0 in round 1 — the test fell back to `data.user.email`; strengthened) |
| M22 | email stored in clear | 1 |
| M23 | email not normalised | 1 |
| M24 | kdt map unbounded | 1 |
| M25 | oversized kdt kept | 1 |
| M26 | push without Bearer | 1 |
| M27 | revokeToken not kept | 6 |
| M28 | revoke ignores kept token | 2 |
| M29 | kept token not forgotten | 1 |
| M30 | edge challenge -> UNAUTHORIZED | 1 |
| M31 | revoke-token map unbounded | 1 |
| M32 | 4.27.0 constructor dropped | 1 |
| M33 | final not read | 1 |
| N1 | no byte budget | 4 |
| N2 | no bisection (multi-event 400/413/422 dropped) | 4 |
| N3 | IDENTITY_UNVERIFIED permanent | 1 |
| N4 | no null compaction in the queue | 1 |
| N5 | payload writes null projectId | 1 |
| N6 | reset clears kdt | 1 |
| N7 | deleteAccount keeps kdt | 1 |
| N8 | deleteAccount forgets every account | 1 |
| N9 | Retry-After overflow | 1 |
| N10 | screen names unbounded | 1 |
| P1 | identity-rejected not kept | 2 |
| P2 | code ignored | 1 |
| P3 | no reason fallback | 1 |
| P4 | reason read even with a code | 1 |
| P5 | kept events spend no attempt | 2 |
| P6 | pass continues after kept | 2 |
| R1 | edge challenge spends budget | 2 |
| R2 | 429 spends budget | 1 |
| R3 | Cloudflare 52x/530 spend budget | 1 |
| R4 | cap snaps back after a lone drop | 1 |
| R5 | no POST budget | 1 |
| R6 | no backoff after the budget | 1 |
| R7 | no 5xx bisection | 1 |
| R8 | 5xx halves on the first failure | 3 |
| R9 | no doubling back after success | 3 |
| R10 | token not attached at send | 1 |
| R11 | decorated bytes not counted | 1 |
| R12 | token attached to any user's event | 1 |
| R13 | lone event to /events | 1 |
| S1 | unreadable secure store left null (no recovery) | 2 |
| S2 | recreate without deleting | 2 |
| S3 | recreate more than once | 1 |
| S4 | wipe on any failure (platform errors too) | 1 |
| S5 | cause chain ignored | 1 |
| Q1 | no persist on add | 2 |
| Q2 | persist synchronously inside add | 1 |
| Q3 | no coalescing (a write per add) | 1 |
| G1 | handleBroadcast unguarded without play-services-location | 1 |

**60 / 60 red** — the WHOLE set re-run after round 3 at 112 tests (cp backup under a path-unique name → mutate → suite → restore, byte-identical each). M3 (cf → DROP) is superseded by R1; M20 / N11 by N6 / R9 (the rules they guarded changed). ⚠ Deviations: 429 whole-client hold clamped to 60 s (a per-route 429 — support's per-ticket 600 s —
must not black out events + refresh); offline does not spend the attempt budget; the new revoke overload takes
`revokeToken` without a default (a default would make `revoke(sc) { }` ambiguous with the 4.27.0 overload).
⚠ Not mirror-published; README pin / `SDK_RELEASES` / snippets / golden test are the coordinator's.

## 4.27.0 — Support parity with RN 1.42.0 (s58.376)

`SendoraCloudSupport.kt`: `createTicket` / `listMyTickets` / `getMyTicket` / `replyToMyTicket` (suspend, through
`SendoraCloud.supportTransport()` = the configured `ApiClient`; refusals → `SendoraSupportException`),
`getUnreadCount` now uses that client too (it opened its own `HttpURLConnection` to a HARDCODED production URL —
staging builds polled prod), `deviceContext()` (`SendoraCloud.supportDeviceContext()`: versionName, longVersionCode,
`Build.VERSION.RELEASE`, manufacturer + model, SDK), `sanitizeMetadata` (sorted keys, parity iOS), pure `contactUrl`
(`URLEncoder` = `URLSearchParams`-compatible; token + metadata in the FRAGMENT). Constructor seams
(`transportProvider`, `tokenProvider`, `contextProvider`) keep it unit-testable without Robolectric.
`presentContactWidget` gained `metadata` / `includeDeviceContext` / `attachSession` / `accent` (defaulted, before
`onResult`), `presentTicketHistory` `accent`. Guard `SupportTest.kt` (8); mutations all red.

## 4.26.2 — held-slot refresh identity tripwire (parity RN 1.41.2, s58.360)

Full write-up in the RN CLAUDE.md 1.41.2 section. A held guest's refresh must come back for that guest;
a response for anyone else → `HELD_GUEST_IDENTITY_MISMATCH` before the slot write (claim: no `/merge`;
restore: nothing installed, slot kept). Transport unchanged: `HttpURLConnection` attaches cookies only if the host app installed a default `CookieHandler`. Tests inside `AuthMachineConformanceTest` (claim + restore); tripwire mutation → red; full gate 42/42.

## 4.26.1 — dead session is `SESSION_EXPIRED` again; server detail in `SignedOut.endReason: String? = null` (same shape as `GuestReleased.endReason`; `AuthTx.Clear.endReason`) (RopoLabs, 2026-10-10)

4.26.0 mapped the B11 `endReason` onto `signed_out.reason` (`revoked` / `deleted`). Those are two
OLD situations ("account deleted elsewhere", "sessions revoked") that 4.25.0 reported as
`SESSION_EXPIRED`, so a listener matching `SESSION_EXPIRED` stopped seeing them — RopoLabs' template
(`auth-store.ts:665`) and our own `/docs/auth-errors` example both did. ⚠ **A new union value is
additive only for a NEW situation; re-labelling an existing one is a behaviour change**
(ADR-023), even though it compiles. Fix: `reason` is `SESSION_EXPIRED` for EVERY dead verdict; the
detail is `SignedOut.endReason: String? = null` (same shape as `GuestReleased.endReason`; `AuthTx.Clear.endReason`). The three values stay in the type (never emitted) so 1.41.0-era code compiles.
Shared table row `refresh_dead.current` now emits `signed_out{reason:'session_expired', endReason}`.
Guard `AuthMachineConformanceTest` `refresh_dead.current`; mutations: map revoked/deleted back onto `reason` → 1 red; drop the endReason → 1 red.

## ADR-033 wave 1 (4.26.0) — the auth state machine

Lockstep with RN 1.41.0 / web 3.24.0 / iOS 5.4.0. Spec: `docs/decisions/033-sdk-auth-mechanism.md`
§3.1–3.5, §5 wave 1, §8 defaults. The shared table (`packages/shared/src/auth-machine/`) is THE
spec; this SDK is an interpreter of it.

**Machine.** `SendoraCloudAuth` holds ONE slot (`AuthSlot` = `Empty | Session | Limbo | Withheld`)
→ `status()` = `SIGNED_OUT | ANONYMOUS/IDENTIFIED | UNKNOWN | WITHHELD`. Every write, slot
assignment, cron arm/disarm, emission and parent hook happens in the `commit(AuthTx.*)` arms at
the bottom of the file (INV-1). Identity commits CAS on the `sid` family (`identityKey()`), token
commits on the refresh token SENT (`AuthTx.Rotate.sent`); an unrouted rotation is DROPPED (P16).
`identityAttempt {}` awaits an in-flight refresh at start AND `commitIdentity` at commit.
Session-installing verbs `awaitSettledIfUnknown()` (queued in UNKNOWN, INV-5) and
`rejectIfWithheld()`. Seams: `internal/AuthStore.kt` (`AuthStore` / `AuthTransport` /
`RefreshCron`) — `Storage` / `ApiClient` / `CoroutineRefreshCron` in production, recording doubles
in the JVM suite (`AuthMachineHarness.kt`). This is what finally lets the auth class run
headless — no `Context`.

**Storage (`internal/AuthKeys.kt` is the ONLY file naming a key).** The four frozen keys
(format unchanged) + `auth_session` (dual-write; read-first; write-forward from legacy keys;
`schema_version` → `"2"`) + K=5 fixed held slots `auth_held_0..4` (`{v:1,userId,sid,refreshToken,
tokenAtHold,heldAt,project,autoRestore}`, no access token), all EncryptedSharedPreferences;
`auth_mint_key` (B10, plain tier). ⚠ **Downgrade cycle:** a 4.25.0 signOut/deleteAccount clears
only the frozen keys, so hydrate trusts `auth_session` ONLY when its refresh token equals the
frozen refresh key; anything else is a leftover → `AuthTx.DropLeftoverRecord`, silently. Hence
`writeSlot` writes the frozen keys FIRST and the record LAST (a crash can leave frozen-without-
record, which write-forward repairs, never record-without-frozen). A hydrate of a record the SDK
wrote itself writes NOTHING. ⚠ A held slot's `heldAt` is `max(now, newestHeld + 1)` — strictly
increasing, or two same-millisecond holds tie and "newest" is undefined.

**Guards.** `projectVerdict()` (`internal/ProjectVerdict.kt`, verbatim port, own base64url +
strict UTF-8 decoders): absent claim = UNKNOWN, explicit null = MISMATCH. Judged in
`commit(Install)` BEFORE assignment: hydrate mismatch → WITHHELD with ZERO writes; mint/sign-in
mismatch → `PROJECT_MISMATCH` + fire-and-forget revoke; refresh mismatch → persist the rotated
pair only, `SessionWithheld`; restore → `HeldGuestProjectMismatch` (slot project checked first,
no network). `AuthMachineSets.DEAD_CODES` / `RELEASE_HELD_ON_END_REASONS` are asserted EQUAL to
the fixture's. T = |held| + (current anonymous ? 1 : 0) ≤ K is enforced at MINT
(`totalGuests()`), so a HOLD never displaces.

**Lockstep rulings recorded here.**
- `onAuthStateChanged` emits `Initial(status,user,withheld)` THEN the 4.25.0 `SignedIn(user)`
  replay when a session exists (removing it is an event removal). Pinned by
  `AuthMachineBehaviourTest` "subscribe replays Initial and then the legacy SignedIn".
- **`SendoraCloud.reset()` is NOT an auth call on Android — case (b).** 4.25.0's `reset()` only
  forgot the analytics identity (user id, identity token, device id, session id) and never
  signed out, so 4.26.0 keeps exactly that. `reset(includeHeldGuests)` is accepted for parity
  and has no effect here. The machine's RESET transaction exists as internal
  `resetSession(includeHeldGuests)` (replayed by the conformance row `reset.keeps_held`) and is
  deliberately not wired to the public call.
- Restore emits `SignedIn(RESTORE)` THEN `GuestReleased(RESTORED)` on BOTH paths (explicit
  and the MINT auto-restore) — fixture corrected in packages/shared.
- A gap-fill that recovers an identity (UNKNOWN → session) emits the 4.12.0 `SignedIn` with no
  cause (RN `recover` parity); `UserUpdated(REFRESH)` only when an existing user object changed.

**Also fixed (pre-existing).** `getAccessToken(forceRefresh = true)` was a no-op on a token whose
deadline still claimed life — the re-check under `refreshMutex` handed the same token back; the
proactive anticipation tick had the same defect (it only ever refreshed in the last 30 s, via
the repair path). `refreshAccessToken(staleToken)` now never serves the token the caller
distrusts. UNKNOWN never serves its cached token (the call IS the gap-fill).

**Tests (JVM, `./gradlew testDebugUnitTest`).** `AuthMachineConformanceTest` replays EVERY row of
`auth-transitions.conformance.json` (36, totality both ways — a fixture row with no scenario
fails) + every `projectVerdictCases` entry (19) through the install path it names; the fixture is
found by walking up from `user.dir`, never copied; `emits` order is read off the row where it
was disputed. `AuthMachineBehaviourTest` covers INV-3 across 8 sign-in verbs, signUp routing,
B15 pending-report retry, INV-9 dedupe, B10 mint key, INV-14 bound `switchAccount`, deprecated
`merge`/takeover, integrator test 10, the downgrade cycle, write order, heldAt ordering.

**Pins converted (source text → behaviour, each with an in-file note).** All four
`RefreshUserAdoptionTest` pins and `AuthErrorCoercionTest`'s reuse-guard + "3 raw withLock sites"
pins. One property changed on purpose: "a live user is never overwritten by a rotation" is
superseded by fixture row `refresh_ok.current_match` (a changed user installs +
`UserUpdated(REFRESH)`). The CancellationException-ordering pin stays text (it measures exactly
the ordering it names).

**Mutation record (cp backup → RED → cp restore, md5-proven identical; harness kept out of
tree).** Every §5 Android-scoped mutation turned the suite red: delete identity CAS
(`sign_in.cas_mismatch`) · re-add `prevAnonRefreshToken` (`sign_in.switch`) · mint in unknown
(`unknown.queue`, `refresh_dead.current`) · second `signed_in` on `link()` upgrade · drop
`auth_session` half of dual-write (4 tests) · drop frozen-key half (4) · delete
await-refresh-before-hold (interleaving) · link:true+identified → `/login` · revoke on
alreadyLinked · drop switchAccount comparison · dynamic held key name (3) · `reset()` default
wipes held · no-arg verb with 2 held · mint at T == K · dead newest slot aborts ensureSession ·
claim without persisting rotation · release on reuse/absent (2) · auto-restore after
account_deleted · serve the withheld token · signUp in withheld · verdict only at hydrate · skip
verdict on refresh · absent claim = match (2) · explicit null = match · write `auth_session` in a
withheld hydrate (3) · RESET releases held in withheld · widen DEAD_CODES at call site (2) ·
forceRefresh re-check (2) · drop subscribe SignedIn replay · install an unrouted rotation (2) ·
keep the stale blob · sign-in does not hold (6) · trust a leftover `auth_session` · record before
frozen keys · `deleteAccount` discards held by default · `heldAt = now` tie. **36 / 36 red** (the first
stale-blob mutation did not compile and was replaced by a valid one — a non-compiling mutant proves nothing).

**Upgrade / downgrade experience.** 4.25.0 → 4.26.0: the four frozen keys are read, a coherent
session is written forward into `auth_session` (one write burst at first boot), nothing else
changes. 4.26.0 → 4.25.0: 4.25.0 reads the frozen keys (always dual-written) and ignores
`auth_session` / `auth_held_*`; held guests are invisible to it but survive on disk for a later
upgrade. 4.25.0 sign-out under a 4.26 record → the record is discarded on the next 4.26 boot.
⚠ Not mirror-published; JitPack tag, on-device smoke and the B9 staging live-run are operator
steps.

## 4.25.0 — signInAnonymously() over an identified session is a no-op (RopoLabs A2, parity RN 1.40.0)

Full write-up in the RN CLAUDE.md 1.40.0 section. The reuse guard in
`SendoraCloudAuth.kt` `signInAnonymously` was `existing?.isAnonymous == true &&
storage.authRefreshToken != null`, so over a LIVE ACCOUNT session it fell through, minted
a guest and persisted over the account's tokens with no state event. Now `existing != null
&& storage.authRefreshToken != null`: an identified session is returned as-is; `forceNew =
true` is the single explicit replace. All four SDKs carried the identical guard and ship
the fix in lockstep (RN 1.40.0 / web 3.23.0 / iOS 5.3.0). Version bumped in BOTH files
(4.25.0). ⚠ The 4.14.0 note says the reuse guard "is pinned by source assertions" — that
pin (if it asserts the `isAnonymous == true` text) must move with the guard; see the test
run in STATUS s58.355. ⚠ Not yet mirror-published — JitPack tag + on-device smoke are the
operator step.

## 4.24.0 — event-queue coroutine hardening + foreground flush (Word Hurdle audit)

Found during the RN 1.39.0 cross-SDK audit (RopoLabs reported RN leaking an unhandled
rejection on slow `/api/v1/events`). Android was **not** affected by that bug — its
`ApiClient` returns `null` on timeout/IOException (never throws), `performFlush` wraps
the handler, and the outer `SendoraCloud` scope carries a `CoroutineExceptionHandler`.
Two defence-in-depth / parity gaps closed:

- **Internal `EventQueue` scope now carries a `CoroutineExceptionHandler`** (it had only
  `Dispatchers.IO + SupervisorJob()`, unlike the outer scope). Dormant today — every
  throw point upstream is already caught — but if an unforeseen throw ever reached a
  `scope.launch` here it would hit the app's default handler and crash. Now it logs.
- **Foreground flush.** `ProcessLifecycleOwner` `onStart` now `scope.launch {
  eventQueue?.flush() }` — parity with RN 1.39.0 + iOS. Before, the queue flushed only
  on the 30 s timer, the size threshold, and consent-grant; returning to foreground (when
  the network is most likely back) is the natural moment to deliver a backlog banked while
  offline. Timer/threshold flushes are unchanged.

Additive; no frozen SharedPreferences key/header/route/wire shape touched (ADR-023), no
public signature changed. Version bumped in BOTH `build.gradle.kts` + `SdkVersion.kt`
(4.24.0). ⚠ Not yet mirror-published — the JitPack tag + on-device smoke are the
operator step (as with every native release).

## 4.23.0 — no device fingerprinting (parity with iOS 5.2.0, SudokuHurdle)

**Removed the capability.** `FingerprintGenerator` is **deleted**; the SDK no longer
computes or transmits a device fingerprint. Same fix + rationale as iOS 5.2.0 (see
there): `init()` (default `autoStartAttribution = true`) used to compute + auto-POST a
device-signal hash to `/attribution/install` on first launch. The auto install report
now carries deterministic signals only (`deviceId`/`appVersion`/`os`/`osVersion`);
`/attribution/deferred` drops the fingerprint. `autoStartAttribution` stays `true`
(it also gates session-start tracking). Less policy-critical off-Apple than iOS, but
kept in lockstep. ADR-023 safe (removed a body field the backend treats as optional).
`./gradlew :compileReleaseKotlin` BUILD SUCCESSFUL. Version bumped in BOTH files (4.23.0).

## 4.22.0 — deviceId survives identify/upgrade (SudokuHurdle r6)

Parity with RN 1.38.0 (full write-up there). The device (anonymous analytics) id
rotated on EVERY auth transition — including the anon→identified upgrade where the
server preserves the `sub`. It now survives identify/upgrade and rotates only at a
person-boundary. `onAnonymousWipe` gained a `Boolean` (rotateDeviceId);
`wipeLocalIdentity` passes `reason == WipeReason.USER || reason == WipeReason.ACCOUNT_DELETED`,
so `REPLACED` (sign-in/upgrade) and `SESSION_EXPIRED` clear the userId but KEEP the
`device_id` (same person → pre-auth analytics link to them), while an explicit
`signOut()` and the public `reset()` still rotate it (shared-device isolation:
`coalesce(user_id, anonymous_id)` makes the anon id the identity only while signed
out). ADR-023 safe: the `device_id` EncryptedSharedPreferences key is unchanged, only
the value's regeneration frequency drops. Alias/merge stays server-authoritative
(`prevAnonRefreshToken` → `user_upgraded`/`user_merged`). `./gradlew
:compileReleaseKotlin` BUILD SUCCESSFUL. Version bumped in BOTH `build.gradle.kts` +
`SdkVersion.kt` (4.22.0).

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
- Event queue persisted as sent (s58.405: `userId` kept; the identity token never written).
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
