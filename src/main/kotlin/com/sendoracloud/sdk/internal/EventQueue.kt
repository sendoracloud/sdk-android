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
    private var flushHandler: (suspend (List<Map<String, Any?>>) -> Unit)? = null
    private var flushJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    init {
        // Load persisted events
        val persisted = storage.loadEventQueue()
        if (persisted.isNotEmpty()) {
            events.addAll(persisted)
            SendoraCloudLogger.debug("Loaded ${persisted.size} persisted events")
        }
    }

    fun setFlushHandler(handler: suspend (List<Map<String, Any?>>) -> Unit) {
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
        mutex.withLock {
            events.add(event)
            if (events.size > maxSize) {
                events.subList(0, events.size - maxSize).clear()
            }
            if (events.size >= flushAt) {
                performFlush()
            }
        }
    }

    suspend fun flush() {
        mutex.withLock { performFlush() }
    }

    suspend fun persistToDisk() {
        mutex.withLock {
            storage.saveEventQueue(events.toList())
            SendoraCloudLogger.debug("Persisted ${events.size} events to disk")
        }
    }

    private suspend fun performFlush() {
        if (events.isEmpty()) return
        val batch = events.toList()
        events.clear()
        storage.clearEventQueue()
        SendoraCloudLogger.debug("Flushing ${batch.size} events")
        flushHandler?.invoke(batch)
    }

    val count: Int get() = events.size
}
