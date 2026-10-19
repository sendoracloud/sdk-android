package com.sendoracloud.sdk.internal

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The persistence seam the queue writes through. `Storage` implements it in
 * production (the frozen `event_queue` key, ADR-023 §3.4 — format unchanged);
 * the JVM suite substitutes an in-memory double.
 *
 * Per-event attempt counts (4.28.0) live under their OWN additive key, a JSON
 * int array parallel to `event_queue` — never inside an event, because whatever
 * an event carries is sent to the backend. A count list whose length disagrees
 * with the queue (a 4.27.0 wrote the queue last) is ignored: every event
 * restarts at 0, which is the pre-4.28.0 behaviour.
 */
internal interface EventQueueStore {
    fun loadEventQueue(): List<Map<String, Any?>>
    fun saveEventQueue(events: List<Map<String, Any?>>)
    fun clearEventQueue()
    fun loadEventAttempts(): List<Int>
    fun saveEventAttempts(attempts: List<Int>)
}

/** What a flush handler reports back for one chunk. */
internal sealed class FlushResult {
    /** Not sent at all (consent not granted yet) — no attempt is counted, no backoff. */
    object Deferred : FlushResult()

    /**
     * The send's outcome. `status == 0` = no answer (offline, timeout, the
     * breaker refused locally). [retryAfterSeconds] = the server's
     * `Retry-After`; [cfMitigated] = Cloudflare challenged the request.
     */
    data class Sent(
        val status: Int,
        val retryAfterSeconds: Long? = null,
        val cfMitigated: Boolean = false,
        /** The refusal's `error.code`, when it had one (`IDENTITY_UNVERIFIED` is a 401 that is NOT permanent). */
        val errorCode: String? = null,
        /**
         * On a 2xx: the chunk positions the backend refused for IDENTITY only
         * (`data.rejected[i]`, see [identityRejectedIndices]). Those events are
         * kept and spend one attempt; everything else in the chunk is removed.
         */
        val identityRejected: Set<Int> = emptySet(),
    ) : FlushResult()
}

/** How the queue treats one chunk's answer. */
internal enum class FlushVerdict {
    /** 2xx — remove the chunk. */
    ACCEPTED,

    /** A permanent 4xx — resending the same bytes can never succeed: DROP the chunk. */
    DROP,

    /**
     * 400 / 413 / 422 on a MULTI-event chunk: one event (or the sheer size) is
     * the problem, not every event — halve the chunk and resend; only a single
     * event still refused is dropped.
     */
    BISECT,

    /** The backend answered "not now" (408 / 5xx / identity 401 / unknown 4xx) — keep, count an attempt, back off. */
    RETRY,

    /**
     * No answer from the BACKEND (offline, an edge challenge, Cloudflare 520–527 / 530) or a 429 (the caller's own
     * budget) — keep, back off (the server's wait honoured), but do NOT spend the retry budget.
     */
    RETRY_UNANSWERED,
}

/** The permanent refusals: malformed (400), unauthenticated (401), forbidden (403), no such route (404), too large (413), invalid (422). */
internal val PERMANENT_FLUSH_STATUSES: Set<Int> = setOf(400, 401, 403, 404, 413, 422)

/**
 * The positions in a 2xx batch answer that were refused for IDENTITY (s58.402):
 * `data.rejected[i] = { index, reason, code }` with `code == "IDENTITY_UNVERIFIED"`,
 * or — for a row with no code — a `reason` containing "identity" (any case).
 * Answered-transient (the identity token may verify later), like the whole-chunk
 * `401 IDENTITY_UNVERIFIED`. Every other rejected row is a permanent per-event
 * refusal and is removed with the accepted events, as before.
 */
internal fun identityRejectedIndices(body: Map<String, Any?>?, chunkSize: Int): Set<Int> {
    val data = body?.get("data") as? Map<*, *> ?: return emptySet()
    val rows = data["rejected"] as? List<*> ?: return emptySet()
    val out = mutableSetOf<Int>()
    for (row in rows) {
        val r = row as? Map<*, *> ?: continue
        val index = (r["index"] as? Number)?.toInt() ?: continue
        if (index !in 0 until chunkSize) continue
        val code = r["code"] as? String
        val identity = if (code != null) {
            code == "IDENTITY_UNVERIFIED"
        } else {
            (r["reason"] as? String)?.contains("identity", ignoreCase = true) == true
        }
        if (identity) out += index
    }
    return out
}

/** Cloudflare's "the origin never answered" statuses (520–527, 530) — unanswered, no budget spent. */
internal val CLOUDFLARE_ORIGIN_DOWN_STATUSES: Set<Int> = (520..527).toSet() + 530

/** The refusals that can be about ONE event (or the body's size) rather than the whole request. */
internal val BISECT_FLUSH_STATUSES: Set<Int> = setOf(400, 413, 422)

internal fun classifyFlush(status: Int, cfMitigated: Boolean, errorCode: String? = null, chunkSize: Int = 1): FlushVerdict = when {
    // ⚠ FIRST: an edge challenge arrives as a 403 / 503 that the backend never
    // saw. Read as a 403 it would DROP a chunk the backend would have accepted.
    // An edge challenge is not the backend's answer either: back off (≥ 60 s),
    // but spend no budget (round 3, shared rule across the four SDKs).
    cfMitigated -> FlushVerdict.RETRY_UNANSWERED
    status in 200..299 -> FlushVerdict.ACCEPTED
    status == 0 -> FlushVerdict.RETRY_UNANSWERED
    // 429 = the caller's own budget, not a verdict on these events: wait the
    // server's Retry-After, spend nothing.
    status == 429 -> FlushVerdict.RETRY_UNANSWERED
    // Cloudflare's own 52x / 530 (origin unreachable / timed out / handshake…):
    // the backend never answered.
    status in CLOUDFLARE_ORIGIN_DOWN_STATUSES -> FlushVerdict.RETRY_UNANSWERED
    // The backend's strict identity binding: the identity token did not verify
    // (yet) — answered, transient, bounded by the attempt budget. Never a drop.
    status == 401 && errorCode == "IDENTITY_UNVERIFIED" -> FlushVerdict.RETRY
    status in BISECT_FLUSH_STATUSES && chunkSize > 1 -> FlushVerdict.BISECT
    status in PERMANENT_FLUSH_STATUSES -> FlushVerdict.DROP
    // 408 / 5xx — and any 4xx not listed above (402 plan gate, 409, …):
    // kept, but bounded by the per-event attempt cap, so nothing waits forever.
    else -> FlushVerdict.RETRY
}

/**
 * Thread-safe event queue with batched flushing and offline persistence.
 *
 * 4.28.0 (audit F67) — the defects that made a backlog permanent:
 *  - The flush sent the WHOLE queue (up to [maxSize] = 1000) as ONE batch, and
 *    `/events/batch` accepts 1–100 (`batchEventsSchema.max(100)`): once more than
 *    100 events queued offline, every flush was a 400 and the queue never
 *    drained. Now a flush sends chunks of ≤ [maxBatch] events AND ≤
 *    [maxBatchBytes] serialized bytes (the body limit is 64 KB and one event
 *    may carry 32 KB of properties), oldest first. A 400 / 413 / 422 on a
 *    multi-event chunk halves it and resends; only a single event still
 *    refused is dropped.
 *  - A permanent 4xx kept the events at the head forever, so one bad chunk
 *    blocked everything behind it. Now a permanent 4xx DROPS the chunk and the
 *    flush moves on; a transient answer keeps it, counts one attempt per event
 *    (dropped at [maxAttempts]) and backs off with full jitter, never sooner than
 *    the server's `Retry-After` (capped 1 h; an edge challenge ≥ 60 s). A 429,
 *    an edge challenge and Cloudflare 52x / 530 back off without spending budget.
 *  - Round 3: a halved cap stays halved until a success; one flush sends at most
 *    [maxPostsPerFlush] requests; 3 answered 5xx in a row on the same
 *    multi-event chunk halve it; the identity token is attached at SEND time.
 */
/**
 * An event with every null-valued key removed — at the top level and in nested
 * maps, but NOT inside `properties` (a `z.record(z.unknown())` that accepts a
 * null value the app meant). ⚠ Android's built-in `org.json` writes a null map
 * value as JSON `null` and the schema's `.optional()` fields REJECT null
 * (`projectId: null` → 400 for the whole batch); the JVM's org.json 20231013
 * omits nulls, so a JVM test can never see it — hence the strip happens on the
 * map itself, before any serializer. Also strips `JSONObject.NULL` (what a
 * persisted 4.27.0 queue reads back as).
 */
internal fun compactEvent(event: Map<String, Any?>): Map<String, Any?> = compactMap(event, topLevel = true)

private fun isJsonNull(v: Any?): Boolean = v == null || v == org.json.JSONObject.NULL

private fun compactMap(m: Map<*, *>, topLevel: Boolean): Map<String, Any?> {
    val out = LinkedHashMap<String, Any?>()
    for ((k, v) in m) {
        val key = k as? String ?: continue
        if (isJsonNull(v)) continue
        out[key] = if (v is Map<*, *> && !(topLevel && key == "properties")) compactMap(v, topLevel = false) else v
    }
    return out
}

/**
 * Round 3 — attach the CURRENT identity token at send time (RN's `decorate`):
 * only when the event's `userId` IS the identified user and a token is held.
 * The token was stamped at enqueue, so an event kept after an identity refusal
 * could never gain (or refresh) one. An event for anyone else, or with no
 * `userId` (a persisted queue strips it), goes out unchanged.
 */
internal fun decorateWithIdentity(event: Map<String, Any?>, currentUserId: String?, currentToken: String?): Map<String, Any?> {
    if (currentUserId == null || currentToken.isNullOrEmpty()) return event
    if (event["userId"] != currentUserId) return event
    if (event["identityToken"] == currentToken) return event
    return event + ("identityToken" to currentToken)
}

/** Serialized UTF-8 size of one event, as the batch body will carry it. */
internal fun jsonByteSize(event: Map<String, Any?>): Int =
    runCatching { org.json.JSONObject(event).toString().toByteArray(Charsets.UTF_8).size }.getOrDefault(0)

internal class EventQueue(
    private val storage: EventQueueStore,
    private val flushAt: Int = 20,
    private val maxSize: Int = 1000,
    private val maxBatch: Int = MAX_BATCH,
    /** `/events/batch` refuses a body over 64 KB (413); chunks stay under this many serialized bytes. */
    private val maxBatchBytes: Int = MAX_BATCH_BYTES,
    private val sizeOf: (Map<String, Any?>) -> Int = ::jsonByteSize,
    /**
     * Applied to every event at SEND time (never stored): attaches the CURRENT
     * identity token (see `decorateWithIdentity`), so an event kept after an
     * identity refusal can verify once the app has a token. Its bytes count in
     * the [maxBatchBytes] cap.
     */
    private val decorate: (Map<String, Any?>) -> Map<String, Any?> = { it },
    /** At most this many POSTs per flush; past it the queue waits the normal backoff. */
    private val maxPostsPerFlush: Int = MAX_POSTS_PER_FLUSH,
    private val maxAttempts: Int = MAX_ATTEMPTS,
    private val clock: () -> Long = System::currentTimeMillis,
    private val random: (Long) -> Long = Backoff.defaultRandom,
) {
    companion object {
        /** `/events/batch` accepts 1–100 (`packages/shared/src/types/events.ts` `batchEventsSchema`). */
        const val MAX_BATCH = 100

        /** Serialized-bytes budget per chunk (the backend's body limit is 64 KB; ~4.5 KB headroom). */
        const val MAX_BATCH_BYTES = 60_000

        /** One flush sends at most this many requests (a bisection flood is bounded). */
        const val MAX_POSTS_PER_FLUSH = 20

        /** Answered 5xx in a row on the SAME multi-event chunk before it is halved. */
        const val FIVE_XX_BISECT_AFTER = 3

        /** `{"events":[` + `]}` around the chunk. */
        private const val ENVELOPE_BYTES = 13

        /** The per-event retry budget: answered transient failures before the event is dropped. */
        const val MAX_ATTEMPTS = 50
    }

    /** One queued event + its attempt count. Identity (not equality) is what a flush removes by. */
    private class Entry(val event: Map<String, Any?>, var attempts: Int, val bytes: Int)

    private fun entry(event: Map<String, Any?>, attempts: Int): Entry {
        val compact = compactEvent(event)
        return Entry(compact, attempts, sizeOf(compact))
    }

    private val mutex = Mutex()
    private val entries = mutableListOf<Entry>()

    /**
     * Send ONE chunk (≤ [maxBatch]) and report the outcome (ADR-023 §7
     * ack-before-remove). Mirrors iOS.
     */
    private var flushHandler: (suspend (List<Map<String, Any?>>) -> FlushResult)? = null
    private var flushJob: Job? = null

    /**
     * Guards against overlapping flushes racing on the same events (timer tick
     * + threshold auto-flush). Set/cleared only under `mutex`; the network call
     * itself runs OUTSIDE the lock so `add()` is never blocked on I/O.
     */
    private var isFlushing = false

    /** Consecutive transient flush failures (the jitter exponent); 0 after any answer that is not "retry". */
    private var consecutiveFailures = 0

    /** No flush starts before this instant (unix ms). 0 = no backoff. */
    private var nextAttemptAt = 0L

    /**
     * The chunk-size cap. A BISECT halves it and it STAYS halved — across
     * passes, through a dropped lone event — until a SUCCESS, which doubles it
     * back toward [maxBatch] (round 3: a lone drop used to snap it back to 100,
     * so 500 all-bad events cost thousands of POSTs).
     */
    private var cap = maxBatch.coerceAtLeast(1)

    /** Answered 5xx in a row on the chunk that starts with [fiveXxHead] (identity) and has [fiveXxSize] events. */
    private var fiveXxStreak = 0
    private var fiveXxHead: Any? = null
    private var fiveXxSize = 0

    // ⚠ Carries a CoroutineExceptionHandler like the outer SendoraCloud scope does
    // (4.24.0). Every throw point in the flush chain is already caught upstream
    // (ApiClient returns null on timeout/IOException; performFlush wraps the handler),
    // so this is defence-in-depth: an unforeseen throw in a `scope.launch` here logs
    // instead of reaching the app's default uncaught-exception handler and crashing.
    private val scope = CoroutineScope(
        Dispatchers.IO + SupervisorJob() + CoroutineExceptionHandler { _, e ->
            SendoraCloudLogger.error("Event-queue coroutine error", e)
        },
    )

    init {
        // Load persisted events (+ their attempt counts when they still line up).
        val persisted = storage.loadEventQueue()
        if (persisted.isNotEmpty()) {
            val attempts = storage.loadEventAttempts().takeIf { it.size == persisted.size }
            persisted.forEachIndexed { i, e -> entries.add(entry(e, attempts?.get(i)?.coerceAtLeast(0) ?: 0)) }
            SendoraCloudLogger.debug("Loaded ${persisted.size} persisted events")
        }
    }

    fun setFlushHandler(handler: suspend (List<Map<String, Any?>>) -> FlushResult) {
        this.flushHandler = handler
    }

    fun startTimer(intervalMs: Long) {
        flushJob?.cancel()
        flushJob = scope.launch {
            while (isActive) {
                delay(intervalMs)
                flush()
            }
        }
    }

    fun stopTimer() {
        flushJob?.cancel()
        flushJob = null
    }

    suspend fun add(event: Map<String, Any?>) {
        var shouldFlush = false
        mutex.withLock {
            entries.add(entry(event, 0))
            if (entries.size > maxSize) {
                entries.subList(0, entries.size - maxSize).clear()
            }
            shouldFlush = entries.size >= flushAt
        }
        // Flush outside the lock so the HTTP round-trip never blocks concurrent
        // add() callers (the lock only guards the in-memory list mutation).
        if (shouldFlush) performFlush()
    }

    suspend fun flush() {
        performFlush()
    }

    /**
     * Discard every queued event without flushing. Used by Auth on
     * cross-account signin so the prior identity's pending events
     * don't surface under the next user.
     */
    suspend fun dropAll() {
        mutex.withLock {
            entries.clear()
            storage.clearEventQueue()
            storage.saveEventAttempts(emptyList())
        }
    }

    suspend fun persistToDisk() {
        mutex.withLock {
            persistLocked()
            SendoraCloudLogger.debug("Persisted ${entries.size} events to disk")
        }
    }

    private fun persistLocked() {
        storage.saveEventQueue(entries.map { it.event })
        storage.saveEventAttempts(entries.map { it.attempts })
    }

    /**
     * ACK-before-remove flush in chunks (ADR-023 §7, mirrors iOS `EventQueue.swift`).
     *
     *  1. Under the lock: refuse when a flush is in flight or the backoff has not
     *     elapsed; arm `isFlushing`.
     *  2. Loop: snapshot the oldest ≤ [maxBatch] entries, send them OUTSIDE the
     *     lock (events added mid-flight are appended behind and not part of the
     *     chunk), then classify the answer:
     *     ACCEPTED / DROP → remove exactly those entries (by identity) and send
     *     the next chunk; RETRY → count an attempt on each, drop any at the cap,
     *     back off, stop; RETRY_UNANSWERED → back off, stop; Deferred → stop.
     *  3. Re-persist after every chunk so a backlog survives a process restart.
     */
    private suspend fun performFlush() {
        val handler = flushHandler ?: return
        mutex.withLock {
            if (isFlushing) return
            if (entries.isEmpty()) return
            if (clock() < nextAttemptAt) return
            isFlushing = true
        }
        var posts = 0
        var troubled = false
        try {
            while (true) {
                if (posts >= maxPostsPerFlush) {
                    // Budget spent. A pass that only succeeded just stops (the next
                    // tick continues); one that bisected / dropped waits the normal backoff.
                    mutex.withLock { if (troubled && entries.isNotEmpty()) scheduleBackoffLocked(FlushResult.Sent(0)) }
                    break
                }
                val chunk = mutex.withLock { nextChunkLocked(cap) }
                if (chunk.isEmpty()) break
                SendoraCloudLogger.debug("Flushing ${chunk.size} events")
                posts++
                val result = try {
                    handler.invoke(chunk.map { it.second })
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    SendoraCloudLogger.error("Flush handler threw — keeping ${chunk.size} events", e)
                    FlushResult.Sent(0)
                }
                val entriesSent = chunk.map { it.first }
                if (result is FlushResult.Sent &&
                    classifyFlush(result.status, result.cfMitigated, result.errorCode, chunk.size) == FlushVerdict.BISECT
                ) {
                    // Not a verdict on these events yet: nothing removed, no attempt,
                    // no backoff — resend the oldest half. Terminates: the cap halves
                    // every time and a single event can only DROP.
                    troubled = true
                    mutex.withLock { cap = (chunk.size / 2).coerceAtLeast(1) }
                    SendoraCloudLogger.debug("HTTP ${result.status} on ${chunk.size} events — halving to $cap")
                    continue
                }
                val keepGoing = mutex.withLock {
                    val proceed = applyResultLocked(entriesSent, result)
                    persistLocked()
                    proceed
                }
                if (result is FlushResult.Sent && result.status !in 200..299) troubled = true
                if (!keepGoing) break
            }
        } finally {
            withContext(NonCancellable) { mutex.withLock { isFlushing = false } }
        }
    }

    /**
     * The oldest entries that fit BOTH bounds: at most [limit] events and at most
     * [maxBatchBytes] serialized bytes — measured on the event AS SENT (after
     * [decorate]). Always at least one event — an event too big on its own is
     * sent alone, and its 413 drops it.
     */
    private fun nextChunkLocked(limit: Int): List<Pair<Entry, Map<String, Any?>>> {
        val out = mutableListOf<Pair<Entry, Map<String, Any?>>>()
        var bytes = ENVELOPE_BYTES
        for (e in entries) {
            if (out.size >= limit) break
            val wire = decorate(e.event)
            val size = if (wire === e.event) e.bytes else sizeOf(wire)
            val next = bytes + size + (if (out.isEmpty()) 0 else 1)
            if (out.isNotEmpty() && next > maxBatchBytes) break
            out += e to wire
            bytes = next
        }
        return out
    }

    /** A success: clear the failure state and let the cap grow back. */
    private fun succeededLocked() {
        consecutiveFailures = 0
        nextAttemptAt = 0L
        fiveXxStreak = 0
        cap = (cap * 2).coerceAtMost(maxBatch.coerceAtLeast(1))
    }

    /** Apply one chunk's answer under the lock; true = send the next chunk. */
    private fun applyResultLocked(chunk: List<Entry>, result: FlushResult): Boolean {
        val sent = when (result) {
            FlushResult.Deferred -> return false
            is FlushResult.Sent -> result
        }
        return when (classifyFlush(sent.status, sent.cfMitigated, sent.errorCode, chunk.size)) {
            FlushVerdict.ACCEPTED -> {
                val kept = sent.identityRejected.mapNotNull { chunk.getOrNull(it) }
                succeededLocked()
                if (kept.isEmpty()) {
                    removeLocked(chunk)
                    return true
                }
                // The rest went in (or were refused for good); the identity-refused
                // events stay, spend one attempt each, and the pass stops — they sit
                // at the head, so continuing would resend them at once.
                val keptIds = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Entry, Boolean>()).apply { addAll(kept) }
                removeLocked(chunk.filter { it !in keptIds })
                val spent = kept.filter { e -> ++e.attempts >= maxAttempts }
                if (spent.isNotEmpty()) {
                    SendoraCloudLogger.error("Dropping ${spent.size} events after $maxAttempts attempts")
                    removeLocked(spent)
                }
                scheduleBackoffLocked(sent)
                false
            }
            FlushVerdict.DROP -> {
                // The backend refused these bytes for good; resending them would
                // block every event behind them forever. ⚠ The cap is NOT reset here.
                SendoraCloudLogger.error("Events refused permanently (HTTP ${sent.status}) — dropping ${chunk.size}")
                removeLocked(chunk)
                consecutiveFailures = 0
                nextAttemptAt = 0L
                true
            }
            FlushVerdict.RETRY -> {
                noteFiveXxLocked(chunk, sent.status)
                val spent = chunk.filter { e -> ++e.attempts >= maxAttempts }
                if (spent.isNotEmpty()) {
                    SendoraCloudLogger.error("Dropping ${spent.size} events after $maxAttempts attempts")
                    removeLocked(spent)
                }
                scheduleBackoffLocked(sent)
                false
            }
            FlushVerdict.RETRY_UNANSWERED -> {
                scheduleBackoffLocked(sent)
                false
            }
            // Handled before the lock in performFlush; unreachable here.
            FlushVerdict.BISECT -> false
        }
    }

    /**
     * Round 3: one event the server always 500s would poison its whole chunk for
     * the full 50-attempt budget. After [FIVE_XX_BISECT_AFTER] answered 5xx in a
     * row on the SAME multi-event chunk, halve the cap; a lone event just spends
     * its budget.
     */
    private fun noteFiveXxLocked(chunk: List<Entry>, status: Int) {
        if (status < 500 || chunk.size <= 1) {
            fiveXxStreak = 0
            return
        }
        val head = chunk.first()
        if (fiveXxHead === head && fiveXxSize == chunk.size) fiveXxStreak++ else {
            fiveXxHead = head; fiveXxSize = chunk.size; fiveXxStreak = 1
        }
        if (fiveXxStreak >= FIVE_XX_BISECT_AFTER) {
            cap = (chunk.size / 2).coerceAtLeast(1)
            fiveXxStreak = 0
            SendoraCloudLogger.debug("$FIVE_XX_BISECT_AFTER × HTTP 5xx on ${chunk.size} events — halving to $cap")
        }
    }

    private fun removeLocked(gone: List<Entry>) {
        if (gone.isEmpty()) return
        val ids = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Entry, Boolean>())
        ids.addAll(gone)
        entries.removeAll { it in ids }
    }

    private fun scheduleBackoffLocked(sent: FlushResult.Sent) {
        consecutiveFailures++
        val wait = Backoff.delayMs(consecutiveFailures, sent.retryAfterSeconds, sent.cfMitigated, random)
        nextAttemptAt = clock() + wait
        SendoraCloudLogger.debug("Flush deferred ${wait} ms — ${entries.size} events kept for retry")
    }

    val count: Int get() = entries.size

    /** Unix ms before which no flush starts (0 = none). Internal for the JVM suite. */
    internal val backoffUntil: Long get() = nextAttemptAt

    /** The queued events as they will be sent (null-compacted). Internal for the JVM suite. */
    internal fun snapshot(): List<Map<String, Any?>> = entries.map { it.event }

    /** The current chunk-size cap. Internal for the JVM suite. */
    internal val chunkCap: Int get() = cap

    /** Attempt counts in queue order. Internal for the JVM suite. */
    internal fun attemptCounts(): List<Int> = entries.map { it.attempts }
}
