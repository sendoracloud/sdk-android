package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.AuthKeys
import com.sendoracloud.sdk.internal.AuthTransport
import com.sendoracloud.sdk.internal.EventQueue
import com.sendoracloud.sdk.internal.EventQueueStore
import com.sendoracloud.sdk.internal.FlushResult
import com.sendoracloud.sdk.internal.KnownDeviceTokens
import com.sendoracloud.sdk.internal.RichTransport
import com.sendoracloud.sdk.internal.identityRejectedIndices
import com.sendoracloud.sdk.internal.jsonByteSize
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * 4.28.0 — LIVE run of the real Android code against STAGING (never prod).
 *
 * SKIPPED unless `SENDORA_LIVE=1`; the key comes from `SENDORA_PK` (load
 * `.env.e2e.local` into the environment) and must be a staging `pk_dev_` key —
 * it is never printed, logged or written. The base URL is a constant, not an
 * input. Each scenario prints one `LIVE PASS|FAIL <scenario> — evidence` line
 * (no credential, token or address in it) and asserts BEHAVIOUR from the real
 * responses. Paths needing an Android `Context` (`SendoraCloud.init`) are driven
 * through the pieces they call: `buildEventPayload` → `EventQueue` → the batch
 * send `flushEvents` makes; `SendoraCloudAuth` over the real `ApiClient`;
 * `SendoraCloudLinks` / `SendoraCloudPush` over the real `ApiClient`.
 *
 *   SENDORA_LIVE=1 ./gradlew testDebugUnitTest --tests '*LiveStagingTest*' --rerun --no-daemon
 */
@OptIn(ExperimentalCoroutinesApi::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class LiveStagingTest {

    companion object {
        /** STAGING only (`--env dev`, ADR-017). Never an input. */
        const val STAGING = "https://api-dev.sendoracloud.com"
    }

    private lateinit var key: String
    private val run = UUID.randomUUID().toString().substring(0, 8)
    private val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }

    @Before
    fun guard() {
        assumeTrue("live run: set SENDORA_LIVE=1", System.getenv("SENDORA_LIVE") == "1")
        val k = System.getenv("SENDORA_PK") ?: ""
        // ⚠ Never echo the key — only its shape.
        require(!k.startsWith("pk_prod_") && !k.startsWith("pk_live_")) { "refusing a production key" }
        require(k.startsWith("pk_dev_")) { "SENDORA_PK must be a staging pk_dev_ key" }
        key = k
        Dispatchers.setMain(Dispatchers.Unconfined)
    }

    @After
    fun unmain() {
        runCatching { Dispatchers.resetMain() }
    }

    private fun report(scenario: String, pass: Boolean, evidence: String) {
        println("LIVE ${if (pass) "PASS" else "FAIL"} $scenario — $evidence")
    }

    // ─── shared pieces ───────────────────────────────────────────────────────

    private class MemStore : EventQueueStore {
        var events: List<Map<String, Any?>> = emptyList()
        var attempts: List<Int> = emptyList()
        override fun loadEventQueue() = events
        override fun saveEventQueue(events: List<Map<String, Any?>>) { this.events = events }
        override fun clearEventQueue() { events = emptyList() }
        override fun loadEventAttempts() = attempts
        override fun saveEventAttempts(attempts: List<Int>) { this.attempts = attempts }
    }

    private data class Post(val events: Int, val bytes: Int, val nulls: List<String>, val status: Int, val count: Int, val retryAfter: Long?)

    private fun nullPaths(v: Any?, path: String = "$"): List<String> = when (v) {
        null, JSONObject.NULL -> listOf(path)
        is Map<*, *> -> v.flatMap { (k, x) -> if (path == "$.events[]" && k == "properties") emptyList() else nullPaths(x, "$path.$k") }
        is List<*> -> v.flatMap { nullPaths(it, "$path[]") }
        else -> emptyList()
    }

    private val device = mapOf<String, Any>("type" to "phone", "os" to "Android", "osVersion" to "14", "model" to "JVM-live", "appVersion" to "4.28.0-live")

    /** The SDK's own builder, as `trackEvent` calls it — an app initialised WITHOUT a projectId (the M2 case). */
    private fun event(name: String, props: Map<String, Any>, anon: String = "f67-live-$run"): Map<String, Any?> = buildEventPayload(
        projectId = null, name = name, timestamp = iso.format(Date()), properties = props, device = device,
        sessionId = "f67-live-$run", userId = null, anonymousId = anon, identityToken = null,
    )

    /**
     * A queue whose handler performs EXACTLY the send `SendoraCloud.flushEvents` makes
     * (`/events/batch`, `{events}`, the same FlushResult mapping) and records each POST.
     */
    private fun liveQueue(client: ApiClient, posts: MutableList<Post>): EventQueue {
        val q = EventQueue(MemStore(), flushAt = Int.MAX_VALUE, maxSize = 1000)
        q.setFlushHandler { events ->
            val body = mapOf("events" to events)
            val rich = client.sendEvents(EVENTS_BATCH_PATH, body)
            @Suppress("UNCHECKED_CAST")
            val count = ((rich.body?.get("data") as? Map<String, Any?>)?.get("count") as? Number)?.toInt() ?: 0
            posts += Post(events.size, jsonByteSize(body), nullPaths(body), rich.statusCode, count, rich.retryAfterSeconds)
            FlushResult.Sent(
                rich.statusCode, rich.retryAfterSeconds, rich.cfMitigated, rich.errorCode,
                identityRejected = if (rich.statusCode in 200..299) identityRejectedIndices(rich.body, events.size) else emptySet(),
            )
        }
        return q
    }

    /** Flush until empty or [deadlineMs], sleeping through the queue's own backoff. */
    private suspend fun drain(q: EventQueue, deadlineMs: Long, onFlush: () -> Unit = {}) {
        val end = System.currentTimeMillis() + deadlineMs
        while (q.count > 0 && System.currentTimeMillis() < end) {
            onFlush()
            q.flush()
            val wait = q.backoffUntil - System.currentTimeMillis()
            if (q.count > 0) Thread.sleep(wait.coerceIn(250L, 70_000L))
        }
    }

    /** A raw request (no SDK code) — used only to set the stage (exhaust a lane, prove a refusal). */
    private fun raw(path: String, json: String): Pair<Int, String?> {
        val conn = URL("$STAGING/api/v1$path").openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("X-API-Key", key)
        conn.connectTimeout = 10_000; conn.readTimeout = 10_000
        conn.doOutput = true
        OutputStreamWriter(conn.outputStream).use { it.write(json) }
        val code = conn.responseCode
        return code to conn.getHeaderField("Retry-After")
    }

    // ─── 1 ───────────────────────────────────────────────────────────────────

    @Test
    fun s1_250_events_drain_in_bounded_batch_posts_with_no_null_values() = runBlocking {
        val posts = mutableListOf<Post>()
        val q = liveQueue(ApiClient(STAGING, key), posts)
        repeat(250) { q.add(event("f67.live.small", mapOf("i" to it, "run" to run))) }
        drain(q, 180_000)
        val accepted = posts.filter { it.status in 200..299 }.sumOf { it.count }
        // The M2 proof: the backend itself refuses the null the JVM serializer would hide.
        val (nullStatus, _) = raw(EVENTS_BATCH_PATH, """{"events":[{"projectId":null,"module":"custom","eventType":"f67.live.null","properties":{}}]}""")
        val ok = accepted == 250 && posts.all { it.events <= 100 && it.bytes <= 60_000 && it.nulls.isEmpty() } && nullStatus in 400..422
        report("1 250 events", ok, "posts=${posts.map { "${it.events}ev/${it.bytes}B→${it.status}(count ${it.count})" }}, accepted=$accepted, nullPaths=${posts.flatMap { it.nulls }.distinct()}, raw projectId:null → HTTP $nullStatus")
        assertEquals(250, accepted)
        assertTrue(posts.all { it.events <= 100 && it.bytes <= 60_000 })
        assertTrue("no null value in any body", posts.all { it.nulls.isEmpty() })
        assertTrue("the backend refuses projectId:null (HTTP $nullStatus)", nullStatus in 400..422)
    }

    // ─── 2 ───────────────────────────────────────────────────────────────────

    @Test
    fun s2_eight_kb_events_chunk_under_60000_bytes() = runBlocking {
        val posts = mutableListOf<Post>()
        val q = liveQueue(ApiClient(STAGING, key), posts)
        val blob = "x".repeat(7_900)
        repeat(12) { q.add(event("f67.live.big", mapOf("i" to it, "blob" to blob))) }
        drain(q, 120_000)
        val accepted = posts.filter { it.status in 200..299 }.sumOf { it.count }
        val ok = accepted == 12 && posts.all { it.bytes < 60_000 } && posts.size > 1
        report("2 8 KB events", ok, "posts=${posts.map { "${it.events}ev/${it.bytes}B→${it.status}" }}, accepted=$accepted")
        assertEquals(12, accepted)
        assertTrue(posts.all { it.bytes < 60_000 })
        assertTrue("more than one chunk", posts.size > 1)
    }

    // ─── 3 ───────────────────────────────────────────────────────────────────

    @Test
    fun s3_one_bad_event_among_good_ones_is_the_only_drop() = runBlocking {
        val posts = mutableListOf<Post>()
        val q = liveQueue(ApiClient(STAGING, key), posts)
        repeat(5) { q.add(event("f67.live.good", mapOf("i" to it))) }
        q.add(event("x".repeat(200), mapOf("bad" to "eventType over 128"))) // schema 400/422 → the batch bisects
        repeat(5) { q.add(event("f67.live.good", mapOf("i" to 5 + it))) }
        q.add(event("f67.live.oversize", mapOf("blob" to "y".repeat(70_000)))) // alone over 64 KB → 413
        var maxPerFlush = 0
        var flushes = 0
        val end = System.currentTimeMillis() + 180_000
        while (q.count > 0 && System.currentTimeMillis() < end) {
            val before = posts.size
            q.flush(); flushes++
            maxPerFlush = maxOf(maxPerFlush, posts.size - before)
            if (q.count > 0) Thread.sleep((q.backoffUntil - System.currentTimeMillis()).coerceIn(250L, 70_000L))
        }
        val accepted = posts.filter { it.status in 200..299 }.sumOf { it.count }
        val refusals = posts.filter { it.status !in 200..299 }.map { "${it.events}ev→${it.status}" }
        val ok = accepted == 10 && q.count == 0 && maxPerFlush <= 20 && refusals.any { it.startsWith("1ev→413") }
        report("3 bad among good", ok, "accepted=$accepted, refusals=$refusals, posts=${posts.size}, maxPerFlush=$maxPerFlush, flushes=$flushes, left=${q.count}")
        assertEquals("only the two bad events dropped", 10, accepted)
        assertEquals(0, q.count)
        assertTrue(maxPerFlush <= 20)
    }

    // ─── 5 + 7 ───────────────────────────────────────────────────────────────

    /** Records what the SDK SENT (path, body KEYS, header NAMES) — never a value. */
    private class Recording(val delegate: ApiClient) : AuthTransport, RichTransport {
        data class Sent(val path: String, val bodyKeys: Set<String>, val headerNames: Set<String>, val bearer: Boolean)
        val sent = java.util.Collections.synchronizedList(mutableListOf<Sent>())
        private fun note(path: String, body: Map<String, Any?>?, h: Map<String, String>?) {
            sent += Sent(path, body?.keys ?: emptySet(), h?.keys ?: emptySet(), h?.get("Authorization")?.startsWith("Bearer ") == true)
        }
        override suspend fun post(path: String, body: Map<String, Any?>, extraHeaders: Map<String, String>?): Map<String, Any?>? {
            note(path, body, extraHeaders); return delegate.post(path, body, extraHeaders)
        }
        override suspend fun get(path: String, extraHeaders: Map<String, String>?): Map<String, Any?>? {
            note(path, null, extraHeaders); return delegate.get(path, extraHeaders)
        }
        override suspend fun delete(path: String, extraHeaders: Map<String, String>?): Map<String, Any?>? {
            note(path, null, extraHeaders); return delegate.delete(path, extraHeaders)
        }
        override suspend fun requestWithDetails(method: String, path: String, body: Map<String, Any?>?, extraHeaders: Map<String, String>?): ApiClient.RichResponse {
            note(path, body, extraHeaders); return delegate.requestWithDetails(method, path, body, extraHeaders)
        }
    }

    private suspend fun <T> retrying(label: String, block: suspend () -> Result<T>): Result<T> {
        var last: Result<T> = Result.failure(IllegalStateException("not run"))
        repeat(6) { i ->
            last = block()
            val err = last.exceptionOrNull() as? SendoraCloudAuthError
            if (last.isSuccess || err == null || !err.retryable) return last
            println("LIVE note $label: retryable ${err.kind} (${err.code}) — retry ${i + 1}")
            Thread.sleep(((err.retryAfterSeconds ?: 3) * 1000L).coerceIn(2_000L, 30_000L))
        }
        return last
    }

    @Test
    fun s5_s7_known_device_token_and_push_bearer_live() = runBlocking {
        val store = RecordingStore()
        val transport = Recording(ApiClient(STAGING, key))
        val auth = SendoraCloudAuth(
            client = transport, storage = store, onIdentityChange = {}, onAnonymousWipe = {},
            cron = RecordingCron(), background = { b -> runBlocking { runCatching { b() } } },
        )
        val email = "f67-live-android-${run}${SecureRandom().nextInt(1_000_000)}@example.com"
        val password = "F67-live-" + UUID.randomUUID().toString().replace("-", "")
        val steps = mutableListOf<String>()

        val guest = retrying("mint") { auth.signInAnonymously() }
        steps += "guest=${guest.isSuccess}"
        assertTrue("guest mint: ${guest.exceptionOrNull()?.message}", guest.isSuccess)
        Thread.sleep(2_000)
        val up = retrying("signUp") { auth.signUp(email, password) }
        steps += "signUp=${up.isSuccess}${up.exceptionOrNull()?.let { "(${(it as? SendoraCloudAuthError)?.code})" } ?: ""}"
        assertTrue("signUp: ${up.exceptionOrNull()?.message}", up.isSuccess)
        auth.signOut()

        val in1 = retrying("signIn#1") { auth.signIn(email, password) }
        val login1 = transport.sent.last { it.path == "/auth-service/login" }
        val entries1 = KnownDeviceTokens.decode(store.secure[AuthKeys.KNOWN_DEVICE_TOKENS] as? String)
        val keyed = entries1.any { it.key == KnownDeviceTokens.keyFor(email) }
        steps += "signIn#1=${in1.isSuccess}, sentKdt=${"knownDeviceToken" in login1.bodyKeys}, stored=${entries1.size}, keyedBySha256=$keyed, rawEmailOnDisk=${(store.secure[AuthKeys.KNOWN_DEVICE_TOKENS] as? String)?.contains(email) == true}"
        assertTrue(in1.isSuccess)
        assertTrue("staging returned a knownDeviceToken on /login and it is stored under sha256(email)", keyed)

        auth.signOut()
        val in2 = retrying("signIn#2") { auth.signIn(email, password) }
        val login2 = transport.sent.last { it.path == "/auth-service/login" }
        steps += "signIn#2=${in2.isSuccess}, sentKdt=${"knownDeviceToken" in login2.bodyKeys}"
        assertTrue("the second sign-in presents the token", "knownDeviceToken" in login2.bodyKeys)

        auth.resetSession(includeHeldGuests = true)
        val afterReset = KnownDeviceTokens.decode(store.secure[AuthKeys.KNOWN_DEVICE_TOKENS] as? String).any { it.key == KnownDeviceTokens.keyFor(email) }
        steps += "afterReset.kept=$afterReset"
        assertTrue(afterReset)

        val in3 = retrying("signIn#3") { auth.signIn(email, password) }
        assertTrue(in3.isSuccess)

        // ── 7: push registration carries the player's Bearer ──
        val push = SendoraCloudPush(transport, CoroutineScope(Dispatchers.IO), { auth.currentUser?.id }, { auth.getAccessToken() })
        val pushDone = CompletableDeferred<Result<String>>()
        push.registerToken("f67-live-fake-fcm-${UUID.randomUUID()}") { pushDone.complete(it) }
        val pushResult = withTimeout(20_000) { pushDone.await() }
        val pushSent = transport.sent.last { it.path == "/push/tokens" }
        val pushOk = pushResult.isSuccess && pushSent.bearer
        report("7 push Bearer", pushOk, "registered=${pushResult.isSuccess}${pushResult.exceptionOrNull()?.let { " (${it.message})" } ?: ""}, sentAuthorizationBearer=${pushSent.bearer}")

        // ── cleanup + the deleteAccount rule ──
        val del = auth.deleteAccount()
        val afterDelete = KnownDeviceTokens.decode(store.secure[AuthKeys.KNOWN_DEVICE_TOKENS] as? String).any { it.key == KnownDeviceTokens.keyFor(email) }
        steps += "deleteAccount=${del.isSuccess}(${del.getOrNull()?.status}), entryAfterDelete=$afterDelete"
        val ok = keyed && "knownDeviceToken" !in login1.bodyKeys && "knownDeviceToken" in login2.bodyKeys && afterReset && del.isSuccess && !afterDelete
        report("5 knownDeviceToken", ok, steps.joinToString("; "))
        assertTrue("account deleted (cleanup)", del.isSuccess)
        assertFalse("deleteAccount removed the entry", afterDelete)
        assertTrue("push registration", pushResult.isSuccess)
        assertTrue("push sent the Bearer", pushSent.bearer)
    }

    // ─── 6 ───────────────────────────────────────────────────────────────────

    @Test
    fun s6_link_revoke_token_round_trip() = runBlocking {
        val plain = RecordingStore()
        val transport = Recording(ApiClient(STAGING, key))
        val links = SendoraCloudLinks(transport, null, emptyList(), CoroutineScope(Dispatchers.IO), plain)
        val created = CompletableDeferred<Result<SendoraCloudLinks.LinkCreateResult>>()
        links.create(SendoraCloudLinks.LinkCreateInput(title = "f67 live android $run", fallbackUrl = "https://example.com/f67-live")) { created.complete(it) }
        val r = withTimeout(20_000) { created.await() }
        assertTrue("create: ${r.exceptionOrNull()?.message}", r.isSuccess)
        val link = r.getOrThrow()
        val stored = links.storedRevokeToken(link.shortcode) != null
        val revoked = CompletableDeferred<Result<SendoraCloudLinks.LinkRevokeResult>>()
        links.revoke(link.shortcode, null) { revoked.complete(it) }
        val rv = withTimeout(20_000) { revoked.await() }
        val revokeSent = transport.sent.last { "links" in it.path && it.path.endsWith("revoke") }
        val ok = link.revokeToken?.startsWith("lrt_") == true && stored && "revokeToken" in revokeSent.bodyKeys &&
            rv.isSuccess && rv.getOrNull()?.final == true && links.storedRevokeToken(link.shortcode) == null
        report("6 links revokeToken", ok, "revokeTokenOnResult=${link.revokeToken?.startsWith("lrt_")}, kept=$stored, revokeBodyKeys=${revokeSent.bodyKeys}, revoke=${rv.isSuccess}, final=${rv.getOrNull()?.final}, forgotten=${links.storedRevokeToken(link.shortcode) == null}${rv.exceptionOrNull()?.let { ", err=${it.message}" } ?: ""}")
        assertTrue(ok)
    }

    // ─── 4 (last: it exhausts this machine's ingest lane for up to a minute) ─

    @Test
    fun s9_real_429_waits_retry_after_spends_nothing_then_delivers() = runBlocking {
        // Stage: exhaust the ingest lane ("ingest";q=200;w=60) with raw requests until the server says 429.
        val one = """{"events":[{"module":"custom","eventType":"f67.live.stage","anonymousId":"f67-live-$run","properties":{}}]}"""
        val pool = Executors.newFixedThreadPool(12)
        val seen429 = AtomicInteger(0)
        val sent = AtomicInteger(0)
        repeat(260) {
            pool.submit {
                if (seen429.get() < 5) {
                    val (code, _) = runCatching { raw(EVENTS_BATCH_PATH, one) }.getOrDefault(0 to null)
                    sent.incrementAndGet()
                    if (code == 429) seen429.incrementAndGet()
                }
            }
        }
        pool.shutdown(); pool.awaitTermination(120, TimeUnit.SECONDS)
        assertTrue("staging answered 429 after ${sent.get()} raw requests", seen429.get() > 0)

        val posts = mutableListOf<Post>()
        val q = liveQueue(ApiClient(STAGING, key), posts)
        repeat(3) { q.add(event("f67.live.after429", mapOf("i" to it))) }
        val t0 = System.currentTimeMillis()
        q.flush()
        val first = posts.firstOrNull()
        val attemptsAfter429 = q.attemptCounts()
        val waitedFor = q.backoffUntil - t0
        val honoured = first?.status == 429 && first.retryAfter != null && waitedFor >= (first.retryAfter * 1000L) - 1_000L
        val maxAttempts = mutableListOf<Int>()
        drain(q, 240_000) { maxAttempts += (q.attemptCounts().maxOrNull() ?: 0) }
        val delivered = posts.filter { it.status in 200..299 }.sumOf { it.count }
        val ok = honoured && attemptsAfter429.all { it == 0 } && maxAttempts.all { it == 0 } && delivered == 3
        report("4 real 429", ok, "stage: ${sent.get()} raw → ${seen429.get()}×429; first flush HTTP ${first?.status} Retry-After=${first?.retryAfter}s, queue waits ${waitedFor} ms, attempts=$attemptsAfter429 (max during drain ${maxAttempts.maxOrNull()}), then posts=${posts.map { it.status }}, delivered=$delivered after ${System.currentTimeMillis() - t0} ms")
        assertEquals(429, first?.status)
        assertNotNull(first?.retryAfter)
        assertTrue("waited at least Retry-After", honoured)
        assertTrue("no attempt spent", attemptsAfter429.all { it == 0 } && maxAttempts.all { it == 0 })
        assertEquals(3, delivered)
        assertNull(null)
    }
}
