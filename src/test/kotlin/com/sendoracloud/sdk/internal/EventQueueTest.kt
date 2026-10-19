package com.sendoracloud.sdk.internal

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 4.28.0 (F67) — the event queue against a scripted backend.
 *
 * The two shipped defects this pins: (a) the WHOLE queue went out as one batch,
 * so once > 100 events queued offline every flush was a 400 from
 * `batchEventsSchema.max(100)` and the queue never drained; (b) a permanent 4xx
 * kept the chunk at the head forever. Plus the retry contract: transient answers
 * keep the chunk, spend a per-event budget, and back off with full jitter, never
 * sooner than the server's `Retry-After`.
 */
class EventQueueTest {

    private class MemoryStore : EventQueueStore {
        var events: List<Map<String, Any?>> = emptyList()
        var attempts: List<Int> = emptyList()
        override fun loadEventQueue() = events
        override fun saveEventQueue(events: List<Map<String, Any?>>) { this.events = events }
        override fun clearEventQueue() { events = emptyList() }
        override fun loadEventAttempts() = attempts
        override fun saveEventAttempts(attempts: List<Int>) { this.attempts = attempts }
    }

    private var now = 1_760_000_000_000L
    private val chunks = mutableListOf<List<Map<String, Any?>>>()

    private fun event(i: Int): Map<String, Any?> = mapOf("module" to "analytics", "eventType" to "e$i")

    /** A queue whose handler answers from [answers] in order (the last one repeats). */
    private fun queue(
        store: MemoryStore = MemoryStore(),
        maxAttempts: Int = EventQueue.MAX_ATTEMPTS,
        random: (Long) -> Long = { 0L },
        vararg answers: FlushResult,
    ): EventQueue {
        val q = EventQueue(store, flushAt = Int.MAX_VALUE, maxSize = 1000, maxAttempts = maxAttempts, clock = { now }, random = random)
        var i = 0
        q.setFlushHandler { batch ->
            chunks += batch
            answers[minOf(i++, answers.size - 1)]
        }
        return q
    }

    private suspend fun EventQueue.fill(n: Int) = repeat(n) { add(event(it)) }

    // ─── (a) chunking ────────────────────────────────────────────────────────

    @Test
    fun `a backlog over 100 drains in chunks of at most 100, oldest first`() = runBlocking {
        val q = queue(answers = arrayOf(FlushResult.Sent(200)))
        q.fill(250)
        q.flush()
        assertEquals("never more than /events/batch accepts", listOf(100, 100, 50), chunks.map { it.size })
        assertEquals("FIFO", "e0", chunks[0][0]["eventType"])
        assertEquals("e100", chunks[1][0]["eventType"])
        assertEquals("drained", 0, q.count)
    }

    @Test
    fun `the maximum offline backlog (1000) drains in ten chunks`() = runBlocking {
        val q = queue(answers = arrayOf(FlushResult.Sent(200)))
        q.fill(1000)
        q.flush()
        assertEquals(10, chunks.size)
        assertTrue(chunks.all { it.size == 100 })
        assertEquals(0, q.count)
    }

    // ─── (b) permanent 4xx drop the chunk ────────────────────────────────────

    @Test
    fun `a request-wide permanent 4xx drops the chunk and the flush moves on`() = runBlocking {
        for (status in listOf(401, 403, 404)) {
            chunks.clear()
            val q = queue(answers = arrayOf(FlushResult.Sent(status), FlushResult.Sent(200)))
            q.fill(150)
            q.flush()
            assertEquals("$status: both chunks were sent", listOf(100, 50), chunks.map { it.size })
            assertEquals("$status: the refused chunk is gone, nothing blocks behind it", 0, q.count)
            assertEquals("$status: no backoff after an answer", 0L, q.backoffUntil)
        }
    }

    @Test
    fun `a single event still refused 400 413 or 422 is dropped`() = runBlocking {
        for (status in listOf(400, 413, 422)) {
            chunks.clear()
            val q = queue(answers = arrayOf(FlushResult.Sent(status), FlushResult.Sent(200)))
            q.fill(1)
            q.flush()
            assertEquals("$status: sent once", 1, chunks.size)
            assertEquals("$status: dropped", 0, q.count)
        }
    }

    // ─── bisection (400 / 413 / 422 on a multi-event chunk) ──────────────────

    @Test
    fun `a 413 on a multi-event chunk halves it until it fits, dropping nothing`() = runBlocking {
        val q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L })
        q.setFlushHandler { batch -> chunks += batch; FlushResult.Sent(if (batch.size > 25) 413 else 200) }
        q.fill(100)
        q.flush()
        // After an accepted half the limit doubles back (a culprit-free backlog returns to full chunks).
        assertEquals(listOf(100, 50, 25, 50, 25, 50, 25, 25), chunks.map { it.size })
        assertEquals("every event delivered", (0 until 100).map { "e$it" }, chunks.filter { it.size <= 25 }.flatten().map { it["eventType"] })
        assertEquals(0, q.count)
        assertEquals("a bisection is not a failure", 0L, q.backoffUntil)
    }

    @Test
    fun `a 400 or 422 caused by one event drops only that event`() = runBlocking {
        for (status in listOf(400, 422)) {
            chunks.clear()
            val q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L })
            q.setFlushHandler { batch -> chunks += batch; FlushResult.Sent(if (batch.any { it["eventType"] == "e37" }) status else 200) }
            q.fill(100)
            var flushes = 0
            while (q.count > 0 && flushes < 10) {
                val before = chunks.size
                q.flush()
                assertTrue("$status: at most 20 POSTs per flush", chunks.size - before <= EventQueue.MAX_POSTS_PER_FLUSH)
                now += 3_600_001L; flushes++
            }
            val delivered = chunks.filter { c -> c.none { it["eventType"] == "e37" } }.flatten().map { it["eventType"] }.toSet()
            assertEquals("$status: 99 delivered", (0 until 100).map { "e$it" }.toSet() - "e37", delivered)
            assertEquals("$status: queue empty", 0, q.count)
            assertTrue("$status: bounded", chunks.size <= 40)
        }
    }

    @Test
    fun `a 401 IDENTITY_UNVERIFIED is answered-transient, not permanent`() = runBlocking {
        val q = queue(answers = arrayOf(FlushResult.Sent(401, errorCode = "IDENTITY_UNVERIFIED")))
        q.fill(3)
        q.flush()
        assertEquals("kept", 3, q.count)
        assertEquals("spends the budget", List(3) { 1 }, q.attemptCounts())
        assertEquals(FlushVerdict.DROP, classifyFlush(401, false, "UNAUTHORIZED", 3))
    }

    // ─── round 3 ─────────────────────────────────────────────────────────────

    @Test
    fun `a 429, an edge challenge and Cloudflare 52x or 530 back off without spending budget`() = runBlocking {
        val unanswered = listOf(
            FlushResult.Sent(429, 30), FlushResult.Sent(403, cfMitigated = true), FlushResult.Sent(503, cfMitigated = true),
        ) + ((520..527) + 530).map { FlushResult.Sent(it) }
        for (answer in unanswered) {
            val q = queue(answers = arrayOf(answer))
            q.fill(3)
            q.flush()
            assertEquals("$answer: kept", 3, q.count)
            assertEquals("$answer: no attempt spent", List(3) { 0 }, q.attemptCounts())
        }
        val q = queue(answers = arrayOf(FlushResult.Sent(429, 30)))
        q.fill(1); q.flush()
        assertEquals("the server's wait is still honoured", now + 30_000L, q.backoffUntil)
        assertEquals(FlushVerdict.RETRY, classifyFlush(500, false))
        assertEquals(FlushVerdict.RETRY, classifyFlush(528, false))
    }

    @Test
    fun `the halved cap stays halved through a lone drop until a success`() = runBlocking {
        val q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L })
        q.setFlushHandler { b -> chunks += b; FlushResult.Sent(if (b.any { it["eventType"] == "e0" }) 400 else 200) }
        q.fill(4)
        q.flush()
        // 4 → 400 → cap 2; [e0,e1] → 400 → cap 1; [e0] dropped (cap STAYS 1); [e1] ok → 2; [e2,e3] ok.
        assertEquals(listOf(4, 2, 1, 1, 2), chunks.map { it.size })
        assertEquals(0, q.count)
    }

    @Test
    fun `a flood of bad events costs at most 20 POSTs per flush, then the normal backoff`() = runBlocking {
        val q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, maxSize = 1000, clock = { now }, random = { it })
        q.setFlushHandler { b -> chunks += b; FlushResult.Sent(400) }
        q.fill(500)
        q.flush()
        assertEquals(EventQueue.MAX_POSTS_PER_FLUSH, chunks.size)
        assertTrue("waits", q.backoffUntil > now)
        val sent = chunks.size
        q.flush()
        assertEquals("no POST inside the backoff", sent, chunks.size)
        assertTrue("the cap stayed small", q.chunkCap <= 2)
    }

    @Test
    fun `three answered 5xx in a row on the same multi-event chunk halve it`() = runBlocking {
        val q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L })
        q.setFlushHandler { b -> chunks += b; FlushResult.Sent(if (b.any { it["eventType"] == "e2" }) 500 else 200) }
        q.fill(4)
        repeat(2) { q.flush(); now += 3_600_001L }
        assertEquals("two 500s: not yet", 100, q.chunkCap)
        q.flush(); now += 3_600_001L
        assertEquals("the third halves", 2, q.chunkCap)
        q.flush()
        assertEquals("the healthy half goes in", listOf("e2", "e3"), q.snapshot().map { it["eventType"] })
        // [4] ×3 (500) → cap 2; [e0,e1] ok → cap 4; [e2,e3] 500 (a new chunk: streak 1) → stop.
        assertEquals(listOf(4, 4, 4, 2, 2), chunks.map { it.size })
    }

    @Test
    fun `the identity token is attached at send time, counted in the byte cap, never stored`() = runBlocking {
        assertEquals("tok", decorateWithIdentity(mapOf("userId" to "u1"), "u1", "tok")["identityToken"])
        assertEquals("replaces a stale stamp", "tok2", decorateWithIdentity(mapOf("userId" to "u1", "identityToken" to "old"), "u1", "tok2")["identityToken"])
        assertFalse("another user's event", decorateWithIdentity(mapOf("userId" to "u2"), "u1", "tok").containsKey("identityToken"))
        assertFalse("no userId (persisted)", decorateWithIdentity(mapOf("eventType" to "e"), "u1", "tok").containsKey("identityToken"))
        assertFalse("no token held", decorateWithIdentity(mapOf("userId" to "u1"), "u1", null).containsKey("identityToken"))

        val q = EventQueue(
            MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L },
            sizeOf = { if (it.containsKey("identityToken")) 30_000 else 100 },
            decorate = { decorateWithIdentity(it, "u1", "tok") },
        )
        q.setFlushHandler { b -> chunks += b; FlushResult.Sent(500) }
        q.add(mapOf("eventType" to "a", "userId" to "u1"))
        q.add(mapOf("eventType" to "b", "userId" to "u1"))
        q.flush()
        assertEquals("decorated bytes count: 13 + 30000 + 1 + 30000 > 60000", 1, chunks.single().size)
        assertEquals("tok", chunks.single().single()["identityToken"])
        assertTrue("stored events carry no token", q.snapshot().none { it.containsKey("identityToken") })
    }

    // ─── per-event identity refusals inside a 201 (s58.402) ──────────────────

    @Test
    fun `identity-rejected events of a 201 stay and spend one attempt, the rest are removed`() = runBlocking {
        val q = queue(answers = arrayOf(FlushResult.Sent(201, identityRejected = setOf(1, 3))))
        q.fill(5)
        q.flush()
        assertEquals("only the identity refusals are kept", listOf("e1", "e3"), q.snapshot().map { it["eventType"] })
        assertEquals(listOf(1, 1), q.attemptCounts())
        assertEquals("the pass stops (they are at the head)", 1, chunks.size)
    }

    @Test
    fun `the rejected rows are read by code, else by an identity reason - other rows are not kept`() {
        val body = mapOf("success" to true, "data" to mapOf("rejected" to listOf(
            mapOf("index" to 0, "reason" to "x", "code" to "IDENTITY_UNVERIFIED"),
            mapOf("index" to 2, "reason" to "Identity token did not verify"),
            mapOf("index" to 3, "reason" to "eventType too long", "code" to "VALIDATION"),
            mapOf("index" to 4, "reason" to "identity mismatch", "code" to "VALIDATION"),
            mapOf("index" to 9, "code" to "IDENTITY_UNVERIFIED"),
        )))
        assertEquals("a code wins over the reason; out-of-range ignored", setOf(0, 2), identityRejectedIndices(body, 5))
        assertEquals(emptySet<Int>(), identityRejectedIndices(mapOf("success" to true, "data" to mapOf("accepted" to 5)), 5))
    }

    @Test
    fun `identity-rejected events are dropped once their budget is spent`() = runBlocking {
        val q = queue(maxAttempts = 2, answers = arrayOf(FlushResult.Sent(201, identityRejected = setOf(0))))
        q.fill(1)
        q.flush()
        assertEquals(1, q.count)
        now += 3_600_001L
        q.flush()
        assertEquals(0, q.count)
    }

    // ─── the byte budget ─────────────────────────────────────────────────────

    @Test
    fun `chunks stay under 60000 serialized bytes as well as 100 events`() = runBlocking {
        val q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L }, sizeOf = { 1_000 })
        q.setFlushHandler { batch -> chunks += batch; FlushResult.Sent(200) }
        q.fill(150)
        q.flush()
        // 13 envelope bytes + n × 1000 + (n − 1) commas ≤ 60 000  →  n = 59
        assertEquals(listOf(59, 59, 32), chunks.map { it.size })
        assertEquals(0, q.count)
    }

    @Test
    fun `the default sizer measures real UTF-8 bytes and a 32 KB event fits one per chunk pair`() = runBlocking {
        val big = "é".repeat(16_000) // 32 000 UTF-8 bytes, 16 000 chars
        assertTrue(jsonByteSize(mapOf("p" to big)) >= 32_000)
        val q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L })
        q.setFlushHandler { batch -> chunks += batch; FlushResult.Sent(200) }
        repeat(4) { q.add(mapOf("eventType" to "e$it", "properties" to mapOf("p" to big))) }
        q.flush()
        assertEquals("two 32 KB events would exceed 60 000 bytes", listOf(1, 1, 1, 1), chunks.map { it.size })
    }

    @Test
    fun `an event bigger than the budget on its own is still sent, alone`() = runBlocking {
        val q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L }, sizeOf = { 70_000 })
        q.setFlushHandler { batch -> chunks += batch; FlushResult.Sent(413) }
        q.fill(2)
        q.flush()
        assertEquals(listOf(1, 1), chunks.map { it.size })
        assertEquals("each 413 single dropped", 0, q.count)
    }

    // ─── null values never reach the wire ────────────────────────────────────

    @Test
    fun `queued events carry no null values outside properties, whatever the serializer`() = runBlocking {
        val store = MemoryStore()
        // What a 4.27.0 left on disk: Android's org.json read `projectId: null` back as JSONObject.NULL.
        store.events = listOf(mapOf("projectId" to org.json.JSONObject.NULL, "eventType" to "old", "properties" to mapOf("k" to null)))
        val q = EventQueue(store, flushAt = Int.MAX_VALUE, clock = { now })
        q.add(mapOf("projectId" to null, "eventType" to "new", "context" to mapOf("device" to mapOf("model" to null, "os" to "Android"))))
        val sent = q.snapshot()
        assertFalse("projectId never null", sent.any { it.containsKey("projectId") })
        assertEquals(mapOf("os" to "Android"), (sent[1]["context"] as Map<*, *>)["device"])
        assertTrue("a property the app set to null is the app's", (sent[0]["properties"] as Map<*, *>).containsKey("k"))
    }

    // ─── transient answers keep the chunk ────────────────────────────────────

    @Test
    fun `a transient answer keeps the chunk, counts one attempt, and stops the flush`() = runBlocking {
        val transient = listOf(
            FlushResult.Sent(408), FlushResult.Sent(500), FlushResult.Sent(502),
            FlushResult.Sent(503, 10), FlushResult.Sent(409), FlushResult.Sent(402),
        )
        for (answer in transient) {
            chunks.clear()
            val q = queue(answers = arrayOf(answer))
            q.fill(150)
            q.flush()
            assertEquals("$answer: one chunk, then stop", 1, chunks.size)
            assertEquals("$answer: kept", 150, q.count)
            assertEquals("$answer: the sent chunk spent one attempt", List(100) { 1 } + List(50) { 0 }, q.attemptCounts())
            assertTrue("$answer: backing off", q.backoffUntil > now || answer.retryAfterSeconds == null && !answer.cfMitigated)
        }
    }

    @Test
    fun `an edge challenge is never read as a permanent 403`() {
        assertEquals(FlushVerdict.DROP, classifyFlush(403, cfMitigated = false))
        assertEquals(FlushVerdict.RETRY_UNANSWERED, classifyFlush(403, cfMitigated = true))
        assertEquals(FlushVerdict.RETRY_UNANSWERED, classifyFlush(503, cfMitigated = true))
        assertEquals(FlushVerdict.RETRY_UNANSWERED, classifyFlush(200, cfMitigated = true))
        assertEquals(FlushVerdict.RETRY_UNANSWERED, classifyFlush(0, cfMitigated = false))
    }

    @Test
    fun `no answer (offline) keeps everything and spends no retry budget`() = runBlocking {
        val q = queue(maxAttempts = 3, answers = arrayOf(FlushResult.Sent(0)))
        q.fill(10)
        repeat(10) {
            now += 3_600_001L
            q.flush()
        }
        assertEquals(10, chunks.size)
        assertEquals("surviving offline is the queue's job", 10, q.count)
        assertEquals(List(10) { 0 }, q.attemptCounts())
    }

    @Test
    fun `an event is dropped once it has spent its attempt budget`() = runBlocking {
        val q = queue(maxAttempts = 3, answers = arrayOf(FlushResult.Sent(503)))
        q.fill(5)
        repeat(2) { now += 3_600_001L; q.flush() }
        assertEquals(5, q.count)
        assertEquals(List(5) { 2 }, q.attemptCounts())
        now += 3_600_001L
        q.flush()
        assertEquals("the third answered failure spends the budget", 0, q.count)
    }

    @Test
    fun `consent not granted defers without an attempt or a backoff`() = runBlocking {
        val q = queue(answers = arrayOf(FlushResult.Deferred))
        q.fill(3)
        q.flush()
        assertEquals(3, q.count)
        assertEquals(List(3) { 0 }, q.attemptCounts())
        assertEquals(0L, q.backoffUntil)
    }

    // ─── backoff ─────────────────────────────────────────────────────────────

    @Test
    fun `no flush starts before the backoff elapses, and a success clears it`() = runBlocking {
        val q = queue(answers = arrayOf(FlushResult.Sent(503, 30), FlushResult.Sent(200)))
        q.fill(3)
        q.flush()
        assertEquals(now + 30_000L, q.backoffUntil)
        now += 29_999L
        q.flush()
        assertEquals("still inside Retry-After: nothing sent", 1, chunks.size)
        now += 1L
        q.flush()
        assertEquals(2, chunks.size)
        assertEquals(0, q.count)
        assertEquals(0L, q.backoffUntil)
    }

    @Test
    fun `the wait is at least the server's Retry-After, capped at one hour`() = runBlocking {
        val q = queue(answers = arrayOf(FlushResult.Sent(429, 999_999)))
        q.fill(1)
        q.flush()
        assertEquals(now + 3_600_000L, q.backoffUntil)
    }

    @Test
    fun `an edge challenge waits at least 60 s even with no Retry-After`() = runBlocking {
        val q = queue(answers = arrayOf(FlushResult.Sent(403, null, cfMitigated = true)))
        q.fill(1)
        q.flush()
        assertEquals(now + 60_000L, q.backoffUntil)
        assertEquals(1, q.count)
    }

    @Test
    fun `full jitter - random(0, min(60 s, 2^n s))`() {
        val ceilings = mutableListOf<Long>()
        val spy: (Long) -> Long = { bound -> ceilings += bound; bound }
        assertEquals(2_000L, Backoff.delayMs(1, null, false, spy))
        assertEquals(4_000L, Backoff.delayMs(2, null, false, spy))
        assertEquals(32_000L, Backoff.delayMs(5, null, false, spy))
        assertEquals(60_000L, Backoff.delayMs(6, null, false, spy))
        assertEquals(60_000L, Backoff.delayMs(40, null, false, spy))
        assertEquals("the random draw is the WHOLE range, from 0", listOf(2_000L, 4_000L, 32_000L, 60_000L, 60_000L), ceilings)
        assertEquals("a zero draw is allowed (full jitter, not equal jitter)", 0L, Backoff.delayMs(3, null, false) { 0L })
        assertEquals("the server's floor wins over a short draw", 120_000L, Backoff.delayMs(1, 120, false) { 0L })
        assertEquals("a huge Retry-After caps at 1 h instead of overflowing negative", 3_600_000L, Backoff.serverFloorMs(9_300_000_000_000_000L, false))
        assertEquals(3_600_000L, Backoff.serverFloorMs(Long.MAX_VALUE, false))
    }

    @Test
    fun `Retry-After parses delta-seconds and HTTP-dates`() {
        val t = 1_760_000_000_000L // 2025-10-09T08:53:20Z
        assertEquals(120L, Backoff.parseRetryAfter("120", t))
        assertEquals(120L, Backoff.parseRetryAfter(" 120 ", t))
        assertEquals(0L, Backoff.parseRetryAfter("-5", t))
        assertEquals(40L, Backoff.parseRetryAfter("Thu, 09 Oct 2025 08:54:00 GMT", t))
        assertEquals(null, Backoff.parseRetryAfter("soon", t))
        assertEquals(null, Backoff.parseRetryAfter(null, t))
    }

    // ─── persistence + identity ──────────────────────────────────────────────

    @Test
    fun `attempt counts survive a restart, and a mismatched count list is ignored`() = runBlocking {
        val store = MemoryStore()
        val q = queue(store = store, answers = arrayOf(FlushResult.Sent(500)))
        q.fill(4)
        q.flush()
        assertEquals(List(4) { 1 }, store.attempts)
        val reloaded = EventQueue(store, clock = { now })
        assertEquals(List(4) { 1 }, reloaded.attemptCounts())
        store.attempts = listOf(7) // a 4.27.0 rewrote the queue without the counts
        assertEquals(List(4) { 0 }, EventQueue(store, clock = { now }).attemptCounts())
    }

    @Test
    fun `events added while a chunk is in flight are not removed with it`() = runBlocking {
        lateinit var q: EventQueue
        q = EventQueue(MemoryStore(), flushAt = Int.MAX_VALUE, clock = { now }, random = { 0L })
        var first = true
        q.setFlushHandler { batch ->
            chunks += batch
            if (first) { first = false; q.add(event(99)) }
            FlushResult.Sent(if (chunks.size == 1) 200 else 500)
        }
        q.fill(2)
        q.flush()
        assertEquals("the late event went out in its own chunk", listOf(2, 1), chunks.map { it.size })
        assertEquals("…and stays queued after that chunk failed", 1, q.count)
    }

    // ─── 4.29.0: persisted on add (process death in the foreground) ──────────

    private fun awaitTrue(timeoutMs: Long = 3_000, cond: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        while (!cond() && System.currentTimeMillis() < end) Thread.sleep(10)
    }

    @Test
    fun `added events survive process death - a new queue over the same storage restores them`() = runBlocking {
        val store = MemoryStore()
        val before = EventQueue(store, flushAt = Int.MAX_VALUE, persistDelayMs = 20)
        before.fill(7) // below flushAt, never backgrounded, never flushed
        awaitTrue { store.events.size == 7 }
        // The process dies here: nothing else runs. A fresh launch builds a new queue on the same disk.
        val after = EventQueue(store, flushAt = Int.MAX_VALUE, persistDelayMs = 20)
        assertEquals("all 7 restored", 7, after.count)
        assertEquals((0 until 7).map { "e$it" }, after.snapshot().map { it["eventType"] })
    }

    @Test
    fun `the write on add is coalesced and never made inside add itself`() = runBlocking {
        var saves = 0
        val store = object : EventQueueStore {
            var events: List<Map<String, Any?>> = emptyList()
            override fun loadEventQueue() = events
            override fun saveEventQueue(events: List<Map<String, Any?>>) { saves++; this.events = events }
            override fun clearEventQueue() { events = emptyList() }
            override fun loadEventAttempts() = emptyList<Int>()
            override fun saveEventAttempts(attempts: List<Int>) {}
        }
        val q = EventQueue(store, flushAt = Int.MAX_VALUE, persistDelayMs = 500)
        q.fill(50)
        assertEquals("add() returned without writing to disk", 0, saves)
        awaitTrue { saves >= 1 }
        Thread.sleep(700)
        assertEquals("50 adds inside the window = ONE write", 1, saves)
        assertEquals(50, store.events.size)
    }
}
