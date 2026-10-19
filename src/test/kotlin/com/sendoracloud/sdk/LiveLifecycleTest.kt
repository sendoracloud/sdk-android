package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.AuthKeys
import com.sendoracloud.sdk.internal.AuthTransport
import com.sendoracloud.sdk.internal.EventQueue
import com.sendoracloud.sdk.internal.EventQueueStore
import com.sendoracloud.sdk.internal.FlushResult
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.net.CookieHandler
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.URLEncoder
import java.util.UUID

/**
 * ADR-033 B9 live run, the ANDROID port of `scripts/e2e/auth-lifecycle.mts`
 * (steps A1–A7, B1–B5, W1-a/b/c/d/g/g2/e, B8, B9) — THIS SDK's real
 * `SendoraCloudAuth` over the real `ApiClient` / `HttpURLConnection` against
 * STAGING, with a phone-like cookie jar ALWAYS on (a `CookieManager` installed as
 * the default `CookieHandler`, which is exactly what `HttpURLConnection` consults
 * — s58.360: a gate with no jar passed while every real phone failed). Storage is
 * the in-memory [RecordingStore] (the production `Storage` needs a `Context`);
 * one store instance = one device's disk, shared by every SDK instance built on
 * it, which is what makes the cold start (A3) and the withheld hydrate (W1-e) real.
 *
 * SKIPPED unless `SENDORA_LIVE=1`. Fail-fast: the first failing step is
 * recorded and the run stops (a later step on a broken earlier one proves
 * nothing). Results → `SENDORA_LIVE_RESULT` via [LiveReport].
 *
 * ⚠ Every assertion is behavioural (a status, a body field, a token that is now
 * refused). ⚠ Exactly four refresh 401s per run (`refresh-backoff` blocks an IP
 * after 5 in 60 s): B, C, the withheld account token, the deleted account.
 */
class LiveLifecycleTest {
    private val suite = "LiveLifecycleTest"
    private var previousCookies: CookieHandler? = null
    private lateinit var jar: CookieManager

    @Before
    fun setUp() {
        assumeTrue("live run: set SENDORA_LIVE=1", LiveEnv.enabled)
        LiveEnv.api; LiveEnv.key; LiveEnv.logAuth // guards first
        previousCookies = CookieHandler.getDefault()
        jar = CookieManager(null, CookiePolicy.ACCEPT_ALL)
        CookieHandler.setDefault(jar)
    }

    @After
    fun tearDown() {
        if (LiveEnv.enabled) CookieHandler.setDefault(previousCookies)
    }

    // ─── harness ─────────────────────────────────────────────────────────────

    private data class Seen(val method: String, val path: String, val status: Int, val bodyKeys: Set<String>)

    /** Records method / path / outcome of every SDK request (2xx → 200; a refusal → its stamped status; no answer → 0). */
    private inner class Spy(private val delegate: ApiClient) : AuthTransport {
        val seen = java.util.Collections.synchronizedList(mutableListOf<Seen>())
        private fun outcome(r: Map<String, Any?>?): Int = when {
            r == null -> 0
            r["success"] == true -> 200
            else -> ((r["error"] as? Map<*, *>)?.get("status") as? Number)?.toInt() ?: -1
        }
        override suspend fun post(path: String, body: Map<String, Any?>, extraHeaders: Map<String, String>?) =
            delegate.post(path, body, extraHeaders).also { seen += Seen("POST", path, outcome(it), body.keys) }
        override suspend fun get(path: String, extraHeaders: Map<String, String>?) =
            delegate.get(path, extraHeaders).also { seen += Seen("GET", path, outcome(it), emptySet()) }
        override suspend fun delete(path: String, extraHeaders: Map<String, String>?) =
            delegate.delete(path, extraHeaders).also { seen += Seen("DELETE", path, outcome(it), emptySet()) }
        fun last(method: String, path: String): Seen? = seen.lastOrNull { it.method == method && it.path == path }
    }

    private val spy by lazy { Spy(ApiClient(LiveEnv.api, LiveEnv.key)) }
    private val events = java.util.Collections.synchronizedList(mutableListOf<AuthStateChange>())

    private fun newSdk(disk: RecordingStore, expectedProjectId: String? = null, sink: MutableList<AuthStateChange> = events) = SendoraCloudAuth(
        client = spy, storage = disk, onIdentityChange = {}, onAnonymousWipe = {},
        machine = AuthMachineConfig(expectedProjectId = expectedProjectId),
        cron = RecordingCron(),
        background = { b -> runBlocking { runCatching { b() } } },
        eventSink = { sink += it },
    )

    private fun label(e: AuthStateChange): String = e.event + when (e) {
        is AuthStateChange.SignedIn -> e.cause?.let { "{${it.wire}}" } ?: ""
        is AuthStateChange.SignedOut -> "{${e.reason.wire}}"
        is AuthStateChange.UserUpdated -> "{${e.cause.wire}}"
        is AuthStateChange.GuestReleased -> "{${e.reason.wire}}"
        else -> ""
    }
    private fun since(n: Int, list: List<AuthStateChange> = events) = list.drop(n).filter { it !is AuthStateChange.Initial }.joinToString(",") { label(it) }

    private class StepFailed(msg: String) : Exception(msg)
    private val notes = mutableListOf<String>()
    private var failures = mutableListOf<String>()

    private fun ok(cond: Boolean, msg: String) {
        if (cond) notes += msg else failures += msg
    }

    private var stopped = false

    private fun step(id: String, body: suspend () -> Unit) {
        if (stopped) return
        notes.clear(); failures = mutableListOf()
        val threw = runCatching { runBlocking { body() } }.exceptionOrNull()
        if (threw != null) failures += "threw ${threw.javaClass.simpleName}: ${threw.message}"
        val pass = failures.isEmpty()
        LiveReport.record(id, pass, if (pass) notes.joinToString("; ") else "✗ ${failures.joinToString("; ")} | ✓ ${notes.takeLast(6).joinToString("; ")}", suite)
        if (!pass) stopped = true
    }

    private val rand get() = UUID.randomUUID().toString().replace("-", "").substring(0, 8)
    private fun sub(jwt: String?) = LiveHttp.claims(jwt).optString("sub")

    private fun assertRefreshDead(label: String, refreshToken: String) {
        val r = LiveHttp.call("POST", "/auth-service/token/refresh", JSONObject().put("refreshToken", refreshToken))
        ok(r.status == 401, "$label: its refresh token is now refused (${r.status} ${LiveHttp.err(r).optString("code")})")
    }

    private val GC_BOGUS = JSONObject()
        .put("publicKeyUrl", "https://static.gc.apple.com/public-key/gc-prod-9.cer")
        .put("signature", "bm90LWEtcmVhbC1zaWduYXR1cmU=")
        .put("salt", "c2FsdA==")
        .put("timestamp", System.currentTimeMillis())
        .put("teamPlayerId", "T:_e2e_not_a_real_player")
        .put("bundleId", "com.sendora.e2e.invalid")
    private fun gcBogus(extra: Map<String, Any> = emptyMap()) = JSONObject(GC_BOGUS.toString()).apply { extra.forEach { (k, v) -> put(k, v) } }
    private fun zodRejected(r: LiveHttp.Res, field: String) =
        LiveHttp.err(r).optJSONObject("details")?.optJSONObject("fieldErrors")?.has(field) == true

    // ─── the run ─────────────────────────────────────────────────────────────

    @Test
    fun lifecycle() {
        val runStarted = System.currentTimeMillis()
        // ═══ PHASE A — regression probes (s58.271 / s58.272) ═══
        val diskA = RecordingStore()
        var anonId = ""

        step("A1") {
            val s = newSdk(diskA)
            val u = s.signInAnonymously().getOrThrow()
            anonId = u.id
            ok(u.id.isNotEmpty() && u.isAnonymous, "minted an anonymous user (${u.id.take(8)}…)")
            ok(diskA.secure[AuthKeys.REFRESH] != null, "refresh token persisted")
            ok(spy.last("POST", "/auth-service/anonymous")?.status == 200, "POST /auth-service/anonymous → 2xx")
        }
        step("A2") {
            val s = newSdk(diskA)
            val before = diskA.secure[AuthKeys.REFRESH]
            val u = s.signInAnonymously().getOrThrow()
            ok(u.id == anonId, "same user id returned, no new account minted")
            ok(diskA.secure[AuthKeys.REFRESH] == before, "refresh token untouched")
        }
        step("A3") {
            // Expire the access token on DISK (both the frozen key and the session record).
            val past = System.currentTimeMillis() - 60_000
            diskA.secure[AuthKeys.EXPIRES] = past
            (diskA.secure[AuthKeys.SESSION] as? String)?.let { diskA.secure[AuthKeys.SESSION] = JSONObject(it).put("accessExpiresAt", past).toString() }
            val beforeRefresh = diskA.secure[AuthKeys.REFRESH]
            val s = newSdk(diskA) // a real cold start
            ok(s.currentUser?.id == anonId, "session restored from storage")
            val t = s.getAccessToken()
            ok(t != null && t.split(".").size == 3, "REFRESH SUCCEEDED — a fresh access token was minted")
            ok(spy.last("POST", "/auth-service/token/refresh")?.status == 200, "POST /auth-service/token/refresh → 2xx")
            ok(diskA.secure[AuthKeys.REFRESH] != beforeRefresh, "refresh token rotated (a real server round-trip)")
            ok(s.currentUser?.id == anonId, "identity preserved across the refresh")
            ok(sub(t) == anonId, "the new token's sub is still the same account")
            ok(LiveHttp.claims(t).optLong("exp") * 1000 > System.currentTimeMillis(), "the new token is not already expired")
        }
        step("A4") {
            val s = newSdk(diskA)
            val before = diskA.secure[AuthKeys.REFRESH]
            val beforeUser = s.currentUser?.id
            val err = s.signIn("nobody-${System.currentTimeMillis()}@example.invalid", "wrong-password").exceptionOrNull()
            ok(err is SendoraCloudAuthError, "rejected with a SendoraCloudAuthError (${(err as? SendoraCloudAuthError)?.code})")
            ok((err as? SendoraCloudAuthError)?.kind != null, "carries a kind (${(err as? SendoraCloudAuthError)?.kind})")
            ok(diskA.secure[AuthKeys.REFRESH] == before, "refresh token UNCHANGED after the failure")
            ok(s.currentUser?.id == beforeUser, "user UNCHANGED after the failure")
        }
        step("A5") {
            val good = LiveHttp.call("POST", "/auth-service/login/game-center", gcBogus(mapOf("onCredentialInUse" to "reject")))
            ok(!zodRejected(good, "onCredentialInUse"), "\"reject\" passes validation")
            ok(Regex("not configured|signature|bundle", RegexOption.IGNORE_CASE).containsMatchIn(LiveHttp.err(good).optString("message")), "…and reaches the credential verifier (\"${LiveHttp.err(good).optString("message")}\")")
            val bad = LiveHttp.call("POST", "/auth-service/login/game-center", gcBogus(mapOf("onCredentialInUse" to "merge")))
            ok(zodRejected(bad, "onCredentialInUse"), "a bogus policy IS rejected, by name")
            val enumMsg = LiveHttp.err(bad).optJSONObject("details")?.optJSONObject("fieldErrors")?.optJSONArray("onCredentialInUse")?.optString(0) ?: ""
            ok(Regex("'adopt' \\| 'reject'").containsMatchIn(enumMsg), "…naming the exact enum (\"$enumMsg\")")
        }
        step("A6") {
            val s = newSdk(diskA)
            val token = s.getAccessToken()
            ok(token != null, "anonymous session has a usable access token")
            ok(s.currentUser?.isAnonymous == true, "caller is genuinely anonymous")
            val gc = LiveHttp.call("POST", "/auth-service/me/link/game-center", GC_BOGUS, bearer = token)
            val msg = LiveHttp.err(gc).optString("message")
            ok(Regex("not configured|signature|bundle", RegexOption.IGNORE_CASE).containsMatchIn(msg), "anon reached the credential verifier (\"$msg\")")
            ok(!Regex("Anonymous accounts", RegexOption.IGNORE_CASE).containsMatchIn(msg), "…i.e. the anon link guard no longer refuses it")
            val em = LiveHttp.call("POST", "/auth-service/me/link/email", JSONObject().put("email", "e2e-${System.currentTimeMillis()}@example.invalid").put("password", "Sup3rSecret!x"), bearer = token)
            ok(em.status == 200, "link/email promotes an anonymous caller (${em.status})")
            ok(LiveHttp.data(em).optBoolean("upgraded"), "…returning upgraded:true")
            ok(LiveHttp.tokens(em).has("accessToken") && LiveHttp.tokens(em).has("refreshToken"), "…with a fresh token pair")
            ok(LiveHttp.data(em).optJSONObject("user")?.optBoolean("isAnonymous", true) == false, "…and the user is no longer anonymous")
        }
        step("A7") {
            val s = newSdk(diskA)
            s.signOut()
            ok(diskA.secure[AuthKeys.REFRESH] == null, "local session cleared")
        }

        // ═══ PHASE B — the ADR-033 wave-1 lifecycle ═══
        val disk = RecordingStore() // a fresh device
        val runId = "e2e-$rand"
        val email = "$runId@sendora-e2e.invalid"
        val emailTaken = "$runId-taken@sendora-e2e.invalid"
        val password = "E2e-${rand}Aa1!"
        var accountId = ""
        var guestBId = ""; var guestBRefresh = ""
        var guestCId = ""; var guestCRefresh = ""
        var guestDId = ""
        var takenAccountId = ""; var takenAccountAccess = ""
        var orgId = System.getenv("SENDORA_ORG_ID") ?: ""
        val wrongProject = "00000000-0000-4000-8000-00000000dead"
        val sdk = newSdk(disk)
        fun slot0(): JSONObject? = (disk.secure[AuthKeys.HELD_SLOT_KEYS[0]] as? String)?.let { JSONObject(it) }

        step("B1") {
            ok(sdk.status() == AuthStatus.SIGNED_OUT, "status() before any session is SIGNED_OUT (${sdk.status()})")
            val n = events.size
            val u = sdk.signInAnonymously().getOrThrow()
            accountId = u.id
            ok(u.isAnonymous, "guest A minted (${u.id.take(8)}…)")
            ok("mintKey" in (spy.last("POST", "/auth-service/anonymous")?.bodyKeys ?: emptySet()), "the mint carried a mintKey (B10)")
            ok(sdk.status() == AuthStatus.ANONYMOUS, "status() is ANONYMOUS")
            ok(disk.secure[AuthKeys.SESSION] != null, "auth_session written beside the four frozen keys (dual-write)")
            ok(disk.plain[AuthKeys.SCHEMA_VERSION] == AuthKeys.SCHEMA_VERSION_V2, "schema_version bumped to 2 (${disk.plain[AuthKeys.SCHEMA_VERSION]})")
            val c = LiveHttp.claims(sdk.getAccessToken())
            ok(c.optString("sub") == accountId, "JWT sub is the guest")
            ok(c.optBoolean("is_anonymous"), "JWT is_anonymous=true")
            if (orgId.isEmpty()) orgId = c.optString("org")
            ok(orgId.isNotEmpty(), "org resolved (${orgId.take(8)}…) for the delivery-log read")
            ok(c.has("project"), "JWT carries the `project` claim")
            ok(since(n) == "signed_in{mint}", "events: ${since(n)} (ONE signed_in{mint})")
        }
        step("B2") {
            // trackEvent's payload, as SendoraCloud builds it for this session (onIdentityChange → currentUserId),
            // through the real EventQueue and the exact send flushEvents makes.
            val sent = mutableListOf<Pair<Int, Int>>()
            val client = ApiClient(LiveEnv.api, LiveEnv.key)
            val store = object : EventQueueStore {
                var e: List<Map<String, Any?>> = emptyList(); var a: List<Int> = emptyList()
                override fun loadEventQueue() = e
                override fun saveEventQueue(events: List<Map<String, Any?>>) { e = events }
                override fun clearEventQueue() { e = emptyList() }
                override fun loadEventAttempts() = a
                override fun saveEventAttempts(attempts: List<Int>) { a = attempts }
            }
            val q = EventQueue(store, flushAt = Int.MAX_VALUE)
            q.setFlushHandler { evs ->
                val rich = client.sendEvents(EVENTS_BATCH_PATH, eventsBatchBody(evs))
                @Suppress("UNCHECKED_CAST")
                val count = ((rich.body?.get("data") as? Map<String, Any?>)?.get("count") as? Number)?.toInt() ?: 0
                sent += rich.statusCode to count
                FlushResult.Sent(rich.statusCode, rich.retryAfterSeconds, rich.cfMitigated, rich.errorCode)
            }
            q.add(buildEventPayload(null, "e2e.lifecycle", java.time.Instant.now().toString(), mapOf("runId" to runId, "step" to "B2"),
                mapOf("os" to "Android", "model" to "JVM-live"), "s-$runId", userId = accountId, anonymousId = "dev-$runId", identityToken = null))
            // Other agents share this machine's ingest lane: a 429 is the queue's job (wait Retry-After, retry).
            val end = System.currentTimeMillis() + 120_000
            while (q.count > 0 && System.currentTimeMillis() < end) {
                q.flush()
                if (q.count > 0) Thread.sleep((q.backoffUntil - System.currentTimeMillis()).coerceIn(500L, 65_000L))
            }
            val accepted = sent.lastOrNull { it.first in 200..299 }
            ok(accepted != null, "POST /events/batch → ${sent.map { it.first }}")
            ok(accepted?.second == 1, "accepted (count ${accepted?.second}, no strict-identity rejection)")
        }
        step("B3") {
            val before = disk.secure[AuthKeys.REFRESH]
            val n = events.size
            val t = sdk.getAccessToken(forceRefresh = true)
            ok(spy.last("POST", "/auth-service/token/refresh")?.status == 200, "POST /auth-service/token/refresh → 2xx")
            ok(sub(t) == accountId, "sub unchanged")
            ok(disk.secure[AuthKeys.REFRESH] != before, "refresh token rotated")
            ok(JSONObject(disk.secure[AuthKeys.SESSION] as String).optString("refreshToken") == disk.secure[AuthKeys.REFRESH], "auth_session and the frozen key rotated together")
            ok(since(n) == "", "a rotation is not a transition (no event: \"${since(n)}\")")
        }
        step("B4") {
            val n = events.size
            val u = sdk.signUp(email, password, name = runId).getOrThrow()
            ok(spy.last("POST", "/auth-service/me/link/email")?.status == 200, "POST /auth-service/me/link/email → 2xx")
            ok(spy.last("POST", "/auth-service/upgrade") == null, "POST /auth-service/upgrade was NEVER called (INV-4)")
            ok(u.id == accountId, "same user id — a promotion, not a new account")
            ok(!u.isAnonymous, "isAnonymous=false")
            ok(u.email == email, "email set")
            ok(sdk.status() == AuthStatus.IDENTIFIED, "status() is IDENTIFIED")
            ok(LiveHttp.claims(sdk.getAccessToken()).optBoolean("is_anonymous", true) == false, "the new JWT says is_anonymous=false")
            ok(since(n) == "signed_in{link}", "events: ${since(n)} (ONE signed_in{link}, no signed_out)")
            ok(sdk.heldGuests().isEmpty(), "a promotion never holds (same sub)")
        }
        step("B5") {
            val n = events.size
            sdk.signOut()
            ok(disk.secure[AuthKeys.REFRESH] == null, "local refresh token cleared")
            ok(disk.secure[AuthKeys.SESSION] == null, "auth_session cleared")
            ok(sdk.currentUser == null && sdk.status() == AuthStatus.SIGNED_OUT, "currentUser null, status SIGNED_OUT")
            ok(since(n) == "signed_out{user}", "events: ${since(n)}")
            val login = LiveHttp.call("POST", "/auth-service/login", JSONObject().put("email", email).put("password", password))
            ok(login.status == 200 && LiveHttp.data(login).optJSONObject("user")?.optString("id") == accountId, "the account still signs in (${login.status})")
            LiveHttp.tokens(login).optString("refreshToken").takeIf { it.isNotEmpty() }?.let { LiveHttp.call("POST", "/auth-service/token/revoke", JSONObject().put("refreshToken", it)) }
        }
        step("W1-a") {
            Thread.sleep(2_000) // space guest mints (mint limiter, other agents share it)
            val g = sdk.signInAnonymously().getOrThrow()
            guestBId = g.id
            ok(g.isAnonymous && g.id != accountId, "guest B minted (${g.id.take(8)}…), distinct from the account")
            ok(spy.last("POST", "/auth-service/anonymous")?.status == 200, "a FRESH mint")
            val n = events.size
            val r = sdk.signIn(email, password).getOrThrow()
            ok(spy.last("POST", "/auth-service/login")?.status == 200, "POST /auth-service/login → 2xx")
            ok(r.id == accountId, "signed into the account (not the guest)")
            ok(sdk.status() == AuthStatus.IDENTIFIED, "status() IDENTIFIED")
            ok(since(n) == "guest_held,signed_in{sign_in}", "events: ${since(n)} (guest_held then ONE signed_in{sign_in})")
            val held = sdk.heldGuests()
            ok(held.size == 1 && held[0].userId == guestBId, "heldGuests() = [B]")
            val s0 = slot0()
            ok(s0?.optString("userId") == guestBId && !s0.optString("refreshToken").isNullOrEmpty(), "the slot lives at the LITERAL key auth_held_0 with B's refresh token")
            guestBRefresh = s0?.optString("refreshToken") ?: ""
            val jarRt = jar.cookieStore.cookies.firstOrNull { it.name == "sd_rt" }?.value
            ok(!jarRt.isNullOrEmpty() && jarRt != guestBRefresh, "the device's cookie jar holds the ACCOUNT's sd_rt (≠ the held guest's) — what a phone holds after a sign-in")
            ok(sdk.getLastAnonRetirement() == AnonRetirementOutcome.NONE, "anonRetirement = ${sdk.getLastAnonRetirement()?.wire} (server: no guest token was presented)")
            ok(sdk.getLastDeviceTakeover() == null, "onDeviceTakeover never fired")
            ok(spy.last("POST", "/auth-service/guest/held")?.status == 200, "POST /auth-service/guest/held → 2xx (B15 report)")
        }
        step("W1-b") {
            val n = events.size
            val mark = spy.seen.size
            val r = sdk.claimHeldGuest(guestBId).getOrThrow()
            val after = spy.seen.drop(mark)
            ok(spy.last("POST", "/auth-service/merge")?.status == 200, "POST /auth-service/merge → 2xx")
            val refreshIdx = after.indexOfLast { it.path == "/auth-service/token/refresh" }
            val mergeIdx = after.indexOfLast { it.path == "/auth-service/merge" }
            ok(refreshIdx in 0 until mergeIdx, "the held token was refreshed BEFORE the merge")
            ok(r.user.id == accountId, "the current user is still the account (same sub)")
            ok(r.stats.mergedUserId == accountId && r.stats.deletedAnonymousId == guestBId, "stats: merged=${r.stats.mergedUserId.take(8)} deletedAnonymous=${r.stats.deletedAnonymousId.take(8)}")
            ok(since(n) == "user_updated{merge},guest_released{claimed}", "events: ${since(n)}")
            ok(sdk.heldGuests().isEmpty() && slot0() == null, "the slot is released")
            ok(sdk.status() == AuthStatus.IDENTIFIED, "still identified")
            assertRefreshDead("guest B (merged)", guestBRefresh)
        }
        step("W1-c") {
            sdk.signOut()
            Thread.sleep(2_000)
            val g = sdk.signInAnonymously().getOrThrow()
            guestCId = g.id
            ok(g.isAnonymous && g.id != accountId && g.id != guestBId, "guest C minted (${g.id.take(8)}…)")
            ok(sdk.signIn(email, password).getOrThrow().id == accountId, "signed into the account; C is held")
            val accountRefresh = disk.secure[AuthKeys.REFRESH]
            val n = events.size
            val u = sdk.restoreHeldGuest(guestCId).getOrThrow()
            ok(u.id == guestCId && u.isAnonymous, "restored: current user is C, same sub as minted")
            ok(sdk.status() == AuthStatus.ANONYMOUS, "status() ANONYMOUS")
            ok(since(n) == "signed_in{restore},guest_released{restored}", "events: ${since(n)}")
            ok(sdk.heldGuests().isEmpty(), "the slot is released after the install")
            ok(disk.secure[AuthKeys.REFRESH] != accountRefresh, "the account's local tokens are gone (replaced by C's)")
            ok(sub(sdk.getAccessToken()) == guestCId, "the live JWT sub is C")
            val login = LiveHttp.call("POST", "/auth-service/login", JSONObject().put("email", email).put("password", password))
            ok(login.status == 200 && LiveHttp.data(login).optJSONObject("user")?.optString("id") == accountId, "nothing deleted server-side: the account still signs in (${login.status})")
            LiveHttp.tokens(login).optString("refreshToken").takeIf { it.isNotEmpty() }?.let { LiveHttp.call("POST", "/auth-service/token/revoke", JSONObject().put("refreshToken", it)) }
        }
        step("W1-d") {
            ok(sdk.signIn(email, password).getOrThrow().id == accountId, "signed into the account; C is held again")
            guestCRefresh = slot0()?.optString("refreshToken") ?: ""
            ok(guestCRefresh.isNotEmpty() && slot0()?.optString("userId") == guestCId, "C's slot holds its refresh token")
            val accountRefresh = disk.secure[AuthKeys.REFRESH] as String
            val m1 = LiveHttp.call("POST", "/auth-service/guest/discard", JSONObject().put("refreshToken", accountRefresh))
            ok(m1.status == 404, "discard with the ACCOUNT's (non-anonymous) token → ${m1.status}")
            val m2 = LiveHttp.call("POST", "/auth-service/guest/discard", JSONObject().put("refreshToken", guestBRefresh))
            ok(m2.status == 404, "discard with a DEAD guest token (B, merged) → ${m2.status}")
            val m3 = LiveHttp.call("POST", "/auth-service/guest/discard", JSONObject().put("refreshToken", "bogus_$rand$rand"))
            ok(m3.status == 404, "discard with a bogus token → ${m3.status}")
            ok(sdk.heldGuests().size == 1, "the three refusals touched nothing on the device")
            val n = events.size
            sdk.discardHeldGuest(guestCId).getOrThrow()
            ok(spy.last("POST", "/auth-service/guest/discard")?.status == 200, "POST /auth-service/guest/discard → 2xx")
            ok(since(n) == "guest_released{discarded}", "events: ${since(n)}")
            ok(sdk.heldGuests().isEmpty() && slot0() == null, "the slot is released")
            ok(sdk.status() == AuthStatus.IDENTIFIED && sdk.currentUser?.id == accountId, "the current session is untouched")
            assertRefreshDead("guest C (discarded)", guestCRefresh)
        }
        step("W1-g") {
            Thread.sleep(2_000)
            val mint = LiveHttp.call("POST", "/auth-service/anonymous", JSONObject().put("name", "$runId-taken"))
            val promoted = LiveHttp.call("POST", "/auth-service/me/link/email", JSONObject().put("email", emailTaken).put("password", password), bearer = LiveHttp.tokens(mint).optString("accessToken"))
            takenAccountId = LiveHttp.data(promoted).optJSONObject("user")?.optString("id") ?: ""
            takenAccountAccess = LiveHttp.tokens(promoted).optString("accessToken")
            ok(promoted.status == 200 && takenAccountId.isNotEmpty(), "a second account owns the taken email (${takenAccountId.take(8)}…)")
            val userBefore = sdk.currentUser?.id
            val refreshBefore = disk.secure[AuthKeys.REFRESH]
            val n = events.size
            val mark = spy.seen.size
            val e1 = sdk.link(Credential.Password(emailTaken, password)).exceptionOrNull() as? SendoraCloudAuthError
            ok(spy.last("POST", "/auth-service/me/link/email")?.status == 409, "POST /auth-service/me/link/email → ${spy.last("POST", "/auth-service/me/link/email")?.status}")
            ok(e1 != null && e1.status == 409, "link() over an identified account that has an email fails typed (${e1?.code}/${e1?.status})")
            ok(spy.seen.drop(mark).none { it.path in setOf("/auth-service/login", "/auth-service/signup", "/auth-service/upgrade") }, "…and never reached a sign-in / signup / upgrade route (INV-14)")
            ok(sdk.currentUser?.id == userBefore && disk.secure[AuthKeys.REFRESH] == refreshBefore, "nothing mutated on the 409")
            val thrown = sdk.linkEmailPassword(emailTaken, password).exceptionOrNull() as? SendoraCloudAuthError
            ok(thrown?.status == 409, "linkEmailPassword() fails too (${thrown?.code})")
            ok(sub(sdk.getAccessToken(forceRefresh = true)) == accountId, "the session survives the refused links (no revoke-others on a 409)")
            // Gaming link routing (Play Games is Android's gaming provider; Game Center is iOS-only)
            val pgMark = spy.seen.size
            val pgErr = sdk.link(Credential.PlayGames("not-a-real-server-auth-code")).exceptionOrNull()
            val pgCalls = spy.seen.drop(pgMark)
            ok(pgCalls.any { it.path == "/auth-service/me/link/play-games" }, "link(PlayGames) was sent to /me/link/play-games (${pgCalls.firstOrNull { it.path == "/auth-service/me/link/play-games" }?.status})")
            ok(pgCalls.none { it.path == "/auth-service/login/play-games" }, "…and no sign-in route was touched (INV-14)")
            ok(pgErr is SendoraCloudAuthError && sdk.currentUser?.id == accountId, "the bogus credential surfaced as an error (${(pgErr as? SendoraCloudAuthError)?.code}), still the account")
            val soMark = spy.seen.size
            val soErr = sdk.loginSocial(provider = "google", idToken = "not-a-real-id-token", link = true).exceptionOrNull()
            val soCalls = spy.seen.drop(soMark)
            ok(soCalls.any { it.path == "/auth-service/me/link/social" } && soCalls.none { it.path == "/auth-service/login/social" }, "loginSocial(link=true) over identified went to /me/link/social, never /login/social")
            ok(soErr != null && sdk.currentUser?.id == accountId, "refused credential, session unchanged")
            ok(since(n) == "", "no auth-state event from any refusal (got: \"${since(n)}\")")
        }
        step("W1-g2") {
            sdk.signOut()
            Thread.sleep(2_000)
            val g = sdk.signInAnonymously().getOrThrow()
            guestDId = g.id
            ok(g.isAnonymous && g.id !in setOf(accountId, guestBId, guestCId, takenAccountId), "guest D minted (${g.id.take(8)}…)")
            val refreshBefore = disk.secure[AuthKeys.REFRESH]
            val n = events.size
            val mark = spy.seen.size
            val r = sdk.link(Credential.Password(emailTaken, password)).getOrThrow()
            ok(spy.last("POST", "/auth-service/me/link/email")?.status == 409, "POST /auth-service/me/link/email → 409")
            ok(r is LinkResult.CredentialInUse, "link() → ${r.javaClass.simpleName}")
            val ciu = r as? LinkResult.CredentialInUse ?: return@step
            ok(ciu.provider == "password" && ciu.collision?.wire == "email", "typed payload provider=${ciu.provider} collision=${ciu.collision?.wire} (B14)")
            ok(sdk.currentUser?.id == guestDId && disk.secure[AuthKeys.REFRESH] == refreshBefore && since(n) == "", "nothing mutated on the 409, no event")
            ok(spy.seen.drop(mark).none { it.path == "/auth-service/login" }, "the refusal never reached /login (INV-14)")
            val sw = ciu.switchAccount().getOrThrow()
            ok(spy.last("POST", "/auth-service/login")?.status == 200, "switchAccount() → POST /auth-service/login → 2xx (the refused credential, bound)")
            val done = sw as? SignInResult.Done
            ok(done?.user?.id == takenAccountId, "switched into the account that owns the email")
            val prev = done?.previous
            ok(prev?.userId == guestDId && prev.isAnonymous && prev.held, "previous = {D, isAnonymous:true, held:true}")
            ok(since(n) == "guest_held,signed_in{sign_in}", "events: ${since(n)} (the guest is HELD, never retired)")
            ok(sdk.heldGuests().map { it.userId } == listOf(guestDId), "heldGuests() = [D]")
            sdk.discardHeldGuest(guestDId).getOrThrow()
            ok(sdk.heldGuests().isEmpty(), "D discarded (cleanup)")
            sdk.signOut()
            val back = sdk.signIn(email, password).getOrThrow()
            ok(back.id == accountId && sdk.heldGuests().isEmpty(), "signed back into the account from signed_out (nothing held)")
        }
        step("W1-e") {
            val accountRefresh = disk.secure[AuthKeys.REFRESH] as String
            val before = disk.snapshot().toString()
            val writesBefore = disk.writes.size
            val wEvents = mutableListOf<AuthStateChange>()
            val w = newSdk(disk, expectedProjectId = wrongProject, sink = wEvents)
            ok(w.status() == AuthStatus.WITHHELD, "status() is ${w.status()}")
            ok(w.currentUser == null, "currentUser null")
            val info = w.withheld()
            val actual = LiveHttp.claims(disk.secure[AuthKeys.ACCESS] as? String).let { if (it.isNull("project")) null else it.optString("project") }
            ok(info?.userId == accountId && info.expectedProjectId == wrongProject && info.actualProjectId == actual, "withheld() names the user and both projects (actual=${actual?.take(8)})")
            ok(w.getAccessToken() == null && w.accessToken == null && w.getRefreshToken() == null, "getAccessToken() / accessToken / getRefreshToken() all null")
            ok(disk.snapshot().toString() == before && disk.writes.size == writesBefore, "storage is BYTE-IDENTICAL after the withheld hydrate (zero writes)")
            val err = w.signInAnonymously().exceptionOrNull() as? SendoraCloudAuthError
            ok(err?.code == "SESSION_WITHHELD" && err.kind == SendoraCloudAuthErrorKind.CONFIG, "signInAnonymously() rejects ${err?.code} (kind ${err?.kind})")
            val n = wEvents.size
            ok(w.discardWithheld().getOrThrow(), "discardWithheld() → true")
            ok(w.status() == AuthStatus.SIGNED_OUT && disk.secure[AuthKeys.REFRESH] == null && disk.secure[AuthKeys.SESSION] == null, "the four frozen keys + auth_session are cleared")
            ok(since(n, wEvents) == "signed_out{user}", "events: ${since(n, wEvents)}")
            assertRefreshDead("the account's withheld token (discardWithheld revokes like signOut)", accountRefresh)
        }
        step("B8") {
            // The withheld instance cleared the disk; a fresh instance on it = a cold start, signed out.
            val dev = newSdk(disk)
            ok(dev.status() == AuthStatus.SIGNED_OUT, "a cold start on the cleared disk is SIGNED_OUT")
            ok(dev.signIn(email, password).getOrThrow().id == accountId, "signed back into the account")
            val accountRefresh = disk.secure[AuthKeys.REFRESH] as String
            val n = events.size
            val d = dev.deleteAccount().getOrThrow()
            ok(spy.last("DELETE", "/auth-service/me")?.status == 200, "DELETE /auth-service/me → 2xx")
            ok(d.status == "purged", if (d.status == "pending") "status=pending — the staging project has deletionGraceDays>0" else "status=purged, heldGuests=${d.heldGuests}")
            ok(d.heldGuests == 0, "no held guest left on the device")
            ok(since(n) == "signed_out{account_deleted}", "events: ${since(n)}")
            ok(dev.status() == AuthStatus.SIGNED_OUT, "status() SIGNED_OUT")
            assertRefreshDead("the account", accountRefresh)
            val login = LiveHttp.call("POST", "/auth-service/login", JSONObject().put("email", email).put("password", password))
            ok(login.status == 401, "the credential no longer signs in (${login.status} ${LiveHttp.err(login).optString("code")})")
            val d2 = LiveHttp.call("DELETE", "/auth-service/me", bearer = takenAccountAccess)
            ok(d2.status == 200, "the taken-email account is deleted too (${d2.status})")
        }
        step("B9") {
            val auth = LiveEnv.logAuth
            if (auth == null) { ok(false, "SENDORA_LOG_AUTH is not set — cannot read the org's webhook delivery log"); return@step }
            val headers = if (auth.startsWith("sk_") || auth.startsWith("pk_")) mapOf("x-api-key" to auth) else mapOf("Authorization" to "Bearer $auth")
            data class Want(val type: String, val label: String, val match: (JSONObject) -> Boolean)
            val wants = listOf(
                Want("auth.user_upgraded", "user_upgraded(account)") { it.optString("userId") == accountId },
                Want("auth.guest_held", "guest_held(B)") { it.optString("guestUserId") == guestBId && !it.has("identifiedUserId") },
                Want("auth.user_merged", "user_merged(account←B)") { it.optString("mergedUserId") == accountId && it.optString("deletedAnonymousId") == guestBId },
                Want("auth.user_deleted", "user_deleted(C, guest_discarded)") { it.optString("userId") == guestCId && it.optString("reason") == "guest_discarded" },
                Want("auth.user_deleted", "user_deleted(account)") { it.optString("userId") == accountId },
            )
            val found = mutableMapOf<String, JSONObject>()
            var takeovers = 0
            var lastStatus = 0
            val logsPath = "/orgs/" + orgId + "/webhooks/logs?eventType=" + URLEncoder.encode("auth.", "UTF-8") + "&pageSize=100&withTotal=0"
            val deadline = System.currentTimeMillis() + 45_000
            while (System.currentTimeMillis() < deadline && found.size < wants.size) {
                val res = LiveHttp.call("GET", logsPath, headers = headers, apiKey = null)
                lastStatus = res.status
                val rows = res.body.optJSONArray("data")
                if (res.status == 200 && rows != null) {
                    for (i in 0 until rows.length()) {
                        val row = rows.optJSONObject(i) ?: continue
                        val type = row.optString("eventType", row.optString("event_type"))
                        val ts = runCatching { java.time.Instant.parse(row.optString("createdAt", row.optString("created_at"))).toEpochMilli() }.getOrNull()
                        if (ts != null && ts < runStarted - 5_000) continue
                        val payload = row.optJSONObject("payload") ?: JSONObject()
                        val p = payload.optJSONObject("properties") ?: payload
                        if (type == "auth.device_takeover" && p.optString("anonUserId") in setOf(guestBId, guestCId, guestDId)) takeovers++
                        for (w in wants) if (w.label !in found && type == w.type && w.match(p)) found[w.label] = row
                    }
                }
                if (found.size < wants.size) Thread.sleep(1_500)
            }
            if (found.isEmpty() && lastStatus != 200) {
                ok(false, "GET the org's webhook delivery log → $lastStatus (SENDORA_LOG_AUTH must be an sk_ key with webhooks:read on the staging box)")
                return@step
            }
            for (w in wants) {
                val row = found[w.label]
                ok(row != null, if (row != null) "${w.type} ${w.label} — logged (delivery ${if (row.optBoolean("success")) "succeeded" else "FAILED at the receiver, but dispatched"})" else "${w.type} ${w.label} — not in the delivery log within 45 s")
            }
            ok(takeovers == 0, "no auth.device_takeover row for guest B, C or D (INV-3) — found $takeovers")
        }

        if (stopped) fail("live lifecycle stopped at a failing step — see the LIVE FAIL line")
    }
}
