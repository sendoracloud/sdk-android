package com.sendoracloud.sdk.internal

/**
 * The persistence seam the auth machine writes through (ADR-033 wave 1).
 *
 * `Storage` (EncryptedSharedPreferences + plain SharedPreferences) implements it
 * in production; the JVM conformance suite implements it with an in-memory
 * double that RECORDS every write, so a row that prescribes "zero storage
 * writes" (a withheld hydrate) is asserted byte for byte rather than by
 * reading the source. Keys are the literals in [AuthKeys]; nothing else names
 * one (INV-1).
 *
 * The secure tier fails CLOSED: when it is unavailable a write is refused and
 * logged, never downgraded to plaintext (the pre-4.x fallback exposed tokens on
 * disk). Callers check [isSecureAvailable] before minting anything that would
 * need persisting.
 */
internal interface AuthStore : PlainStore {
    val isSecureAvailable: Boolean

    fun secureGet(key: String): String?

    /** `null` removes the key. */
    fun securePut(key: String, value: String?)

    /** 0 = absent (the `auth_access_expires` contract). */
    fun secureGetLong(key: String): Long

    /** `<= 0` removes the key. */
    fun securePutLong(key: String, value: Long)

}

/**
 * The plain (non-secret) `sendora_sdk` SharedPreferences tier — the part of
 * [AuthStore] other modules need (4.28.0: the links revoke-token map). Split
 * out so a module that keeps no secret cannot reach the encrypted tier.
 */
internal interface PlainStore {
    fun plainGet(key: String): String?

    /** `null` removes the key. */
    fun plainPut(key: String, value: String?)
}

/**
 * The network seam. `ApiClient` is the production implementation; the suite
 * substitutes a scripted stub that records every request (path, body,
 * headers), which is how "the request carries NO guest hint" (INV-3) and "no
 * network" rows are asserted on what was SENT, not on what the source says.
 *
 * ⚠ Never throws on a non-2xx (s58.335): a refusal is the returned envelope
 * with `success:false` + `error.{code,status,details}`; a transport failure or
 * timeout is `null`. A discarded return therefore hides a refusal — every
 * caller must inspect the value.
 */
internal interface AuthTransport {
    suspend fun post(path: String, body: Map<String, Any?>, extraHeaders: Map<String, String>? = null): Map<String, Any?>?
    suspend fun get(path: String, extraHeaders: Map<String, String>? = null): Map<String, Any?>?
    suspend fun delete(path: String, extraHeaders: Map<String, String>? = null): Map<String, Any?>?
}

/**
 * The proactive-refresh scheduler the commit funnel arms and disarms (INV-1:
 * only `commit()` starts or stops it). The production implementation is the
 * 60 s coroutine tick + the `ProcessLifecycleOwner` foreground tick; the suite
 * installs a recorder so "arm the cron" / "no cron" / "stop the cron" are
 * assertions on calls, not on the source.
 */
internal interface RefreshCron {
    /** Idempotent: a second `arm` while armed is a no-op. */
    fun arm(tick: suspend () -> Unit)
    fun disarm()
    val isArmed: Boolean
}
