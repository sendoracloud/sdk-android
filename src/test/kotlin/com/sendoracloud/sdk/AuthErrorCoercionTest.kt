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
import kotlinx.coroutines.async

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

    // --- behavioural guards (converted from source-text pins, 4.26.0) ------
    //
    // ⚠ PINS CONVERTED (ADR-033 wave 1). Until 4.25.0 the reuse guard and the
    // coercion boundary were pinned by reading SendoraCloudAuth.kt as text —
    // the exact `if (!forceNew && existing != null && storage.authRefreshToken
    // != null)` line, and "exactly 3 raw `mutex.withLock` sites". Both pins
    // went stale the moment the machine moved behind `commit()` (the reuse
    // decision is now a table row; `resetSession` is a 4th legitimate lock
    // site), which is the failure mode of a text pin: it measures spelling, not
    // behaviour. The `AuthStore` / `AuthTransport` seams let the JVM suite drive
    // the real methods, so each pin is now the behaviour it stood in for.

    private val guest = user("aaaaaaaa-0000-4000-8000-000000000001", anonymous = true)
    private val account = user("bbbbbbbb-0000-4000-8000-000000000002", anonymous = false, email = "b@x.io")

    @Test
    fun `signInAnonymously reuses the existing session by default`() = kotlinx.coroutines.runBlocking {
        // Over a guest AND over an identified account (4.25.0 RopoLabs A2): the
        // current user comes back, nothing is minted, nothing is written.
        for (u in listOf(guest, account)) {
            val store = RecordingStore(); store.seedLegacySession(u, jwt(u.id, "sid-${u.id}", anonymous = u.isAnonymous), "r", 2_000_000_000_000L)
            val rig = Rig(store = store)
            val mark = store.writes.size
            assertEquals(u.id, rig.auth.signInAnonymously().getOrThrow().id)
            assertEquals("the reuse path makes no network call", 0, rig.transport.requests.size)
            assertEquals("and writes nothing", mark, store.writes.size)
        }
        // Reuse requires BOTH halves: a cached user with NO refresh token is a
        // stale blob (cleared at hydrate), so a fresh guest is minted.
        val store = RecordingStore(); store.seedLegacySession(guest, jwt(guest.id, "s"), refresh = null, expiresAt = 2_000_000_000_000L)
        val rig = Rig(store = store)
        rig.transport.enqueue("/auth-service/anonymous", sessionEnvelope(user("fresh", true), jwt("fresh", "sf"), "rF"))
        assertEquals("fresh", rig.auth.signInAnonymously().getOrThrow().id)
        assertEquals(1, rig.transport.count("/auth-service/anonymous"))
        // forceNew is the opt-in replace (the guest is HELD, not overwritten).
        val s2 = RecordingStore(); s2.seedLegacySession(guest, jwt(guest.id, "sg"), "rG", 2_000_000_000_000L)
        val r2 = Rig(store = s2)
        r2.transport.enqueue("/auth-service/anonymous", sessionEnvelope(user("fresh", true), jwt("fresh", "sf"), "rF"))
        assertEquals("fresh", r2.auth.signInAnonymously(forceNew = true).getOrThrow().id)
        assertEquals(guest.id, r2.auth.heldGuests().single().userId)
    }

    @Test
    fun `every serialized op goes through the coercion boundary`() = kotlinx.coroutines.runBlocking {
        // (1) serialization: a UI double-submit mints ONE guest.
        val rig = Rig()
        val gate = Gate()
        rig.transport.on("/auth-service/anonymous") { gate.await(); sessionEnvelope(user("fresh", true), jwt("fresh", "sf"), "rF") }
        val a = async(kotlinx.coroutines.Dispatchers.Default) { rig.auth.signInAnonymously() }
        val b = async(kotlinx.coroutines.Dispatchers.Default) { rig.auth.signInAnonymously() }
        kotlinx.coroutines.withTimeout(5_000) { gate.opened.await() }
        kotlinx.coroutines.delay(50)
        gate.release()
        assertEquals("fresh", a.await().getOrThrow().id)
        assertEquals("fresh", b.await().getOrThrow().id)
        assertEquals("the second submit waited and reused the first's session", 1, rig.transport.count("/auth-service/anonymous"))

        // (2) coercion: a throw inside a serialized op comes back as a TYPED failure, never raw.
        val throwing = Rig()
        throwing.transport.on("/auth-service/login") { throw IllegalStateException("boom") }
        throwing.transport.on("/auth-service/anonymous") { throw java.net.SocketTimeoutException("slow") }
        val r1 = throwing.auth.signIn("b@x.io", "pw")
        assertEquals(SendoraCloudAuthErrorKind.UNKNOWN, (r1.exceptionOrNull() as SendoraCloudAuthError).kind)
        val r2 = throwing.auth.signInAnonymously()
        assertEquals("a timeout lands on NETWORK", SendoraCloudAuthErrorKind.NETWORK, (r2.exceptionOrNull() as SendoraCloudAuthError).kind)
        assertEquals("and nothing was installed", AuthStatus.SIGNED_OUT, throwing.auth.status())
    }

    // The one remaining source guard: CancellationException ordering is a
    // property of two catch blocks, not of any observable auth behaviour that a
    // stub could tell apart from a typed failure without a real cancellation
    // race, so it stays a text pin (it measures exactly the ordering it names).
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
