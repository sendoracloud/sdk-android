package com.sendoracloud.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.SocketTimeoutException
import java.util.concurrent.TimeoutException

/**
 * The two account-loss holes closed alongside the wipe-after-validate work.
 *
 * 1. Error coercion — a throwable that escapes a public auth op raw carries no
 *    `kind`, so the offline-first branch an app writes (`kind == NETWORK`)
 *    silently misses the stalled-network case it exists for. Everything is
 *    coerced now, and the DEFAULT is non-fatal: an unmapped failure classifies
 *    as UNKNOWN, never as a dead session.
 * 2. `signInAnonymously()` reuse — minting unconditionally overwrites the
 *    stored refresh token, an anonymous account's only durable handle, on a
 *    perfectly healthy network.
 *
 * The reuse guard itself needs a `Context`-backed `Storage` and so cannot run
 * headless; it is pinned by reading the source, the same way the RN suite pins
 * its wipe ordering. A behavioural check is the operator-owned device smoke.
 */
class AuthErrorCoercionTest {

    // --- asAuthError -------------------------------------------------------

    @Test
    fun `an already-typed error passes through untouched`() {
        // Apps match these by CLASS (`is CredentialInUse`). Rewrapping would
        // break every such check that has already shipped.
        val typed = listOf(
            SendoraCloudAuthError.EmailAlreadyTaken("taken", "CONFLICT", 409),
            SendoraCloudAuthError.AlreadyIdentified("identified", "NOT_ANONYMOUS", 409),
            SendoraCloudAuthError.CredentialInUse("in use", "CREDENTIAL_IN_USE", 409),
            SendoraCloudAuthError.Unauthorized("nope", "UNAUTHORIZED", 401),
            SendoraCloudAuthError.Network("offline"),
            SendoraCloudAuthError.SecureStorageUnavailable("no keystore"),
        )
        for (err in typed) {
            assertSame("${err.javaClass.simpleName} is returned as-is", err, asAuthError(err))
        }
    }

    @Test
    fun `a timeout classifies as network, not unknown`() {
        // SocketTimeoutException extends InterruptedIOException, so the connect
        // and the read timeout both have to land on NETWORK — this is the
        // stalled-carrier case an offline-first app branches on.
        for (t in listOf(SocketTimeoutException("read timed out"), TimeoutException("timed out"))) {
            val err = asAuthError(t)
            assertEquals(SendoraCloudAuthErrorKind.NETWORK, err.kind)
            assertEquals("NETWORK_TIMEOUT", err.code)
            assertTrue("a timeout is worth retrying", err.retryable)
        }
    }

    @Test
    fun `an unmapped throwable is UNKNOWN and never session-fatal`() {
        val err = asAuthError(IllegalStateException("something nobody anticipated"))
        assertEquals(SendoraCloudAuthErrorKind.UNKNOWN, err.kind)
        assertEquals("UNKNOWN_ERROR", err.code)
        assertFalse("UNKNOWN must not be reported as retryable", err.retryable)
        // The load-bearing part: an unmapped failure must not look like a dead
        // credential, or the refresh path would learn to wipe on it.
        assertNotEquals(SendoraCloudAuthErrorKind.INVALID_CREDENTIAL, err.kind)
    }

    @Test
    fun `a message-less throwable still produces a usable message`() {
        val err = asAuthError(NullPointerException())
        assertEquals("NullPointerException", err.message)
        assertEquals(SendoraCloudAuthErrorKind.UNKNOWN, err.kind)
    }

    // --- classify ----------------------------------------------------------

    @Test
    fun `classify falls back to status, then to UNKNOWN`() {
        assertEquals(SendoraCloudAuthErrorKind.NETWORK, SendoraCloudAuthErrorKind.classify("NETWORK_TIMEOUT"))
        assertEquals(SendoraCloudAuthErrorKind.RATE_LIMITED, SendoraCloudAuthErrorKind.classify("SOME_NEW_CODE", 429))
        assertEquals(SendoraCloudAuthErrorKind.SERVER, SendoraCloudAuthErrorKind.classify("SOME_NEW_CODE", 503))
        assertEquals(SendoraCloudAuthErrorKind.INVALID_CREDENTIAL, SendoraCloudAuthErrorKind.classify("SOME_NEW_CODE", 401))
        // No code the SDK knows and no status — the non-fatal default.
        val unknown = SendoraCloudAuthErrorKind.classify("SOME_NEW_CODE", null)
        assertEquals(SendoraCloudAuthErrorKind.UNKNOWN, unknown)
        assertFalse(unknown.retryable)
    }

    // --- source guards -----------------------------------------------------

    private val source: String by lazy {
        val relative = "src/main/kotlin/com/sendoracloud/sdk/SendoraCloudAuth.kt"
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, relative)
            if (candidate.isFile) return@lazy candidate.readText()
            dir = dir.parentFile
        }
        ""
    }

    @Test
    fun `signInAnonymously reuses the existing anonymous session by default`() {
        assertTrue("source located", source.isNotEmpty())
        assertTrue(
            "forceNew is opt-in — reuse has to be the default",
            source.contains("forceNew: Boolean = false"),
        )
        assertTrue(
            "reuse requires BOTH a cached anonymous user and a refresh token on disk",
            source.contains("if (!forceNew && existing?.isAnonymous == true && storage.authRefreshToken != null)"),
        )
        assertTrue(
            "the reuse path returns without a network call",
            source.contains("return@serialize Result.success(existing)"),
        )
    }

    @Test
    fun `every serialized op goes through the coercion boundary`() {
        assertTrue("source located", source.isNotEmpty())
        assertTrue(
            "serialize owns the mutex AND the coercion, so a new op cannot miss it",
            source.contains("mutex.withLock { guardedResult(block) }"),
        )
        // The ONLY remaining raw `mutex.withLock` call sites are signOut and the
        // passkey installSession lambda; anything else means an op slipped the
        // boundary.
        val rawLocks = Regex("""\bmutex\.withLock""").findAll(source).count()
        assertEquals("raw mutex.withLock sites (serialize + signOut + passkeys)", 3, rawLocks)
    }

    @Test
    fun `cancellation is rethrown before the catch-all`() {
        assertTrue("source located", source.isNotEmpty())
        // Ordering is load-bearing: a cancellation reported as a failure would
        // hide itself from the caller's scope and outlive the work it belongs to.
        val cancelFirst = Regex(
            """catch \(e: CancellationException\) \{\s*throw e\s*\} catch \(t: Throwable\)""",
        )
        assertEquals(
            "guardedResult + guardedValue both rethrow CancellationException first",
            2,
            cancelFirst.findAll(source).count(),
        )
    }
}
