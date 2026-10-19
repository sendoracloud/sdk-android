package com.sendoracloud.sdk.internal

import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.ThreadLocalRandom

/**
 * 4.28.0 (audit F67) — the retry arithmetic the transport breaker and the event
 * queue share, kept pure so the JVM suite drives it with a fixed clock and a
 * scripted random source.
 *
 * Contract the backend guarantees (s58.402): every 429 (the caller's own budget)
 * and every 503 (overload) carries `Retry-After: <seconds>` AND the same number
 * in `error.details.retryAfterSeconds`. Cloudflare may answer a challenge with
 * `cf-mitigated: challenge` (403 / 503) — an edge decision, never an auth or a
 * permanent verdict.
 */
internal object Backoff {
    /** Full-jitter ceiling: random(0, min(60 s, 2^n s)). */
    const val MAX_JITTER_MS = 60_000L

    /** A server-supplied wait is honoured up to an hour — longer is a bug or an attack, not a schedule. */
    const val MAX_SERVER_WAIT_MS = 3_600_000L

    /** An edge challenge is never retried sooner than this. */
    const val CF_MITIGATED_FLOOR_MS = 60_000L

    /** Uniform in [0, bound] (inclusive); 0 when the bound is not positive. */
    val defaultRandom: (Long) -> Long = { bound -> if (bound <= 0L) 0L else ThreadLocalRandom.current().nextLong(bound + 1) }

    /**
     * The wait after the [failures]-th consecutive failure (n >= 1):
     * `max(random(0, min(60 s, 2^n s)), serverFloor)` where the server floor is
     * `Retry-After` capped at 1 h, raised to 60 s when the edge challenged.
     */
    fun delayMs(
        failures: Int,
        retryAfterSeconds: Long?,
        cfMitigated: Boolean,
        random: (Long) -> Long = defaultRandom,
    ): Long {
        val n = failures.coerceIn(0, 16)
        val ceiling = minOf(MAX_JITTER_MS, (1L shl n) * 1000L)
        val jitter = random(ceiling).coerceIn(0L, ceiling)
        return maxOf(jitter, serverFloorMs(retryAfterSeconds, cfMitigated))
    }

    /** `Retry-After` (capped 1 h) — at least 60 s on an edge challenge; 0 when neither applies. */
    fun serverFloorMs(retryAfterSeconds: Long?, cfMitigated: Boolean): Long {
        // ⚠ Cap the SECONDS before multiplying: a huge Retry-After (Long.MAX_VALUE / 1000 + 1 …)
        // overflowed `* 1000` to a negative, and the server's wait was then ignored entirely.
        val server = (retryAfterSeconds ?: 0L).coerceIn(0L, MAX_SERVER_WAIT_MS / 1000L) * 1000L
        return if (cfMitigated) maxOf(server, CF_MITIGATED_FLOOR_MS) else server
    }

    /**
     * Parse a `Retry-After` header: delta-seconds or an HTTP-date (RFC 9110
     * §10.2.3). Null when absent or unparseable; never negative.
     */
    fun parseRetryAfter(header: String?, nowMs: Long): Long? {
        val raw = header?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        raw.toLongOrNull()?.let { return it.coerceAtLeast(0L) }
        return runCatching {
            val at = ZonedDateTime.parse(raw, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli()
            ((at - nowMs) / 1000L).coerceAtLeast(0L)
        }.getOrNull()
    }

    /** `cf-mitigated: challenge` (any non-empty value counts — Cloudflare documents `challenge` only today). */
    fun isCfMitigated(header: String?): Boolean = !header.isNullOrBlank()
}
