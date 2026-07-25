package com.sendoracloud.sdk.internal

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Thread-safe event queue with batched flushing and offline persistence.
 */
internal class EventQueue(
    private val storage: Storage,
    private val flushAt: Int = 20,
    private val maxSize: Int = 1000,
) {
    private val mutex = Mutex()
    private val events = mutableListOf<Map<String, Any?>>()
    /**
     * Send a snapshot of events; the handler reports back whether the backend
     * ACCEPTED them (ADR-023 §7). On `false` (offline / 5xx / 400) the events
     * stay queued for the next flush — no silent data loss. Mirrors iOS.
     */
    private var flushHandler: (suspend (List<Map<String, Any?>>) -> Boolean)? = null
    private var flushJob: Job? = null
    /**
     * Guards against overlapping flushes racing on the same events (timer tick
     * + threshold auto-flush). Set/cleared only under `mutex`; the network call
     * itself runs OUTSIDE the lock so `add()` is never blocked on I/O.
     */
    private var isFlushing = false
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    init {
        // Load persisted events
        val persisted = storage.loadEventQueue()
        if (persisted.isNotEmpty()) {
            events.addAll(persisted)
            SendoraCloudLogger.debug("Loaded ${persisted.size} persisted events")
        }
    }

    fun setFlushHandler(handler: suspend (List<Map<String, Any?>>) -> Boolean) {
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
            events.add(event)
            if (events.size > maxSize) {
                events.subList(0, events.size - maxSize).clear()
            }
            shouldFlush = events.size >= flushAt
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
            events.clear()
            storage.clearEventQueue()
        }
    }

    suspend fun persistToDisk() {
        mutex.withLock {
            storage.saveEventQueue(events.toList())
            SendoraCloudLogger.debug("Persisted ${events.size} events to disk")
        }
    }

    /**
     * ACK-before-remove flush (ADR-023 §7, mirrors iOS `EventQueue.swift`).
     *
     * The previous version cleared the queue BEFORE the HTTP call, so any flush
     * 5xx / network error permanently lost the batch. Now we:
     *  1. Snapshot the front of the queue under the lock (and arm `isFlushing`
     *     so a concurrent timer + threshold flush don't double-send).
     *  2. Hand the snapshot to the handler OUTSIDE the lock — the HTTP round-trip
     *     never blocks `add()`. New events that arrive mid-flush are appended to
     *     the back and are NOT part of this snapshot.
     *  3. On success, remove exactly the snapshotted events from the FRONT
     *     (FIFO — they're the oldest, mid-flight adds sit behind them) and
     *     re-persist the remainder. On failure, leave everything queued for the
     *     next flush; re-persist so an offline batch survives a process restart.
     */
    private suspend fun performFlush() {
        val handler = flushHandler ?: return
        val batch: List<Map<String, Any?>>
        mutex.withLock {
            if (isFlushing) return
            if (events.isEmpty()) return
            batch = events.toList()
            isFlushing = true
        }

        SendoraCloudLogger.debug("Flushing ${batch.size} events")
        val accepted = try {
            handler.invoke(batch)
        } catch (e: Exception) {
            SendoraCloudLogger.error("Flush handler threw — keeping ${batch.size} events", e)
            false
        }

        mutex.withLock {
            if (accepted) {
                // Drop exactly the events we just sent. They sit at the front of
                // the buffer (FIFO); anything add()ed mid-flight was appended to
                // the back, so removing the first N is correct even if N now
                // exceeds nothing — clamp defensively.
                val removeCount = minOf(batch.size, events.size)
                if (removeCount > 0) events.subList(0, removeCount).clear()
            } else {
                SendoraCloudLogger.debug("Flush rejected — ${events.size} events kept for retry")
            }
            // Persist current in-memory state either way: on success the
            // remainder, on failure the still-queued batch (durability across
            // process restart).
            storage.saveEventQueue(events.toList())
            isFlushing = false
        }
    }

    val count: Int get() = events.size
}
