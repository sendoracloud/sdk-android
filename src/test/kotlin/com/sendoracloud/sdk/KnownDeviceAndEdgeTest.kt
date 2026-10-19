package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.AuthKeys
import com.sendoracloud.sdk.internal.KnownDeviceTokens
import com.sendoracloud.sdk.internal.TestHttpResponder
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 4.28.0 — `knownDeviceToken` (server F23: a device token exempts THIS device
 * from the account-wide login lockouts) and the edge-challenge rule on auth
 * calls (F67: `cf-mitigated` is never a dead credential and never wipes a
 * session). Asserted on what the scripted transport SAW and the recording store
 * HOLDS.
 */
class KnownDeviceAndEdgeTest {

    private val uB = user("bbbbbbbb-0000-4000-8000-000000000002", anonymous = false, email = "b@x.io")
    private val uD = user("dddddddd-0000-4000-8000-000000000004", anonymous = false, email = "d@x.io")
    private val kdtB = "kdt1.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

    private fun loginOk(u: SendoraCloudAuthUser, refresh: String, kdt: String?) =
        sessionEnvelope(u, jwt(u.id, "sid-${u.id}-$refresh", anonymous = false), refresh, extra = kdt?.let { mapOf("knownDeviceToken" to it) } ?: emptyMap())

    private fun Rig.loginBodies() = transport.sent("/auth-service/login").map { it.body!! }

    @Test
    fun `a login's device token is kept encrypted and sent on the next login for that email`() = runBlocking {
        val rig = Rig()
        rig.transport.enqueue("/auth-service/login", loginOk(uB, "r1", kdtB), loginOk(uB, "r2", null), loginOk(uD, "r3", null))
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        assertFalse("the first login has nothing to send", rig.loginBodies()[0].containsKey("knownDeviceToken"))
        val stored = rig.store.secure[AuthKeys.KNOWN_DEVICE_TOKENS] as String
        assertFalse("keyed by a hash, never the address", stored.contains("b@x.io"))
        assertTrue("secure tier only", rig.store.writesTo(AuthKeys.KNOWN_DEVICE_TOKENS).all { it.tier == "secure" })

        rig.auth.signIn("  B@X.io ", "pw").getOrThrow()
        assertEquals("same account, normalised", kdtB, rig.loginBodies()[1]["knownDeviceToken"])
        rig.auth.signIn("d@x.io", "pw").getOrThrow()
        assertFalse("another account never gets B's token", rig.loginBodies()[2].containsKey("knownDeviceToken"))
    }

    @Test
    fun `the token is outside the session slot - it survives sign-out and the reset`() = runBlocking {
        assertFalse(AuthKeys.KNOWN_DEVICE_TOKENS in AuthKeys.SECURE_KEYS)
        assertFalse(AuthKeys.KNOWN_DEVICE_TOKENS in AuthKeys.SLOT_KEYS)
        assertTrue(AuthKeys.KNOWN_DEVICE_TOKENS in AuthKeys.DEVICE_SECRET_KEYS)
        val rig = Rig()
        rig.transport.enqueue("/auth-service/login", loginOk(uB, "r1", kdtB), loginOk(uB, "r2", null), loginOk(uB, "r3", null))
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        rig.auth.signOut()
        assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        assertEquals("survived the sign-out", kdtB, rig.loginBodies()[1]["knownDeviceToken"])
        // The RESET transaction (what an auth-clearing reset runs; apps reset at logout).
        rig.auth.resetSession(includeHeldGuests = true)
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        assertEquals("survived the reset", kdtB, rig.loginBodies()[2]["knownDeviceToken"])
    }

    @Test
    fun `deleteAccount forgets the deleted account's token only`() = runBlocking {
        val kdtD = "kdt1.DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
        val rig = Rig()
        rig.transport.enqueue("/auth-service/login", loginOk(uD, "r1", kdtD), loginOk(uB, "r2", kdtB), loginOk(uD, "r3", null), loginOk(uB, "r4", null))
        rig.transport.on("/auth-service/me") { okEnvelope(mapOf("status" to "pending")) }
        rig.auth.signIn("d@x.io", "pw").getOrThrow()
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        rig.auth.deleteAccount().getOrThrow()
        rig.auth.signIn("d@x.io", "pw").getOrThrow()
        assertEquals("another account keeps its token", kdtD, rig.loginBodies()[2]["knownDeviceToken"])
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        assertFalse("the deleted account's token is gone", rig.loginBodies()[3].containsKey("knownDeviceToken"))
    }

    @Test
    fun `an MFA success files its token under the email that started the challenge`() = runBlocking {
        val rig = Rig()
        rig.transport.enqueue(
            "/auth-service/login",
            okEnvelope(mapOf("mfaRequired" to true, "mfaChallengeToken" to "ct-1", "user" to mapOf("id" to uB.id))),
            loginOk(uB, "r2", null),
        )
        // The challenge envelope's user carries NO email: the token must be filed under the
        // email that started the challenge, not one read back off the response.
        rig.transport.enqueue("/auth-service/mfa/challenge", loginOk(uB.copy(email = null), "r1", kdtB))
        val outcome = rig.auth.signInWithMfaSupport("b@x.io", "pw").getOrThrow()
        assertTrue(outcome is SendoraCloudAuth.SignInOutcome.MfaRequired)
        rig.auth.challengeMfa("ct-1", "123456").getOrThrow()
        assertFalse("the challenge body is unchanged", rig.transport.sent("/auth-service/mfa/challenge").single().body!!.containsKey("knownDeviceToken"))
        rig.auth.signOut()
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        assertEquals(kdtB, rig.loginBodies()[1]["knownDeviceToken"])
    }

    @Test
    fun `a refused login stores nothing, and an oversized token is never kept`() = runBlocking {
        val rig = Rig()
        rig.transport.enqueue(
            "/auth-service/login",
            errorEnvelope("ACCOUNT_LOCKED", 403),
            loginOk(uB, "r1", "k".repeat(2049)),
        )
        assertTrue(rig.auth.signIn("b@x.io", "pw").isFailure)
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        assertTrue(rig.store.writesTo(AuthKeys.KNOWN_DEVICE_TOKENS).isEmpty())
    }

    // s58.405: a lock is retryable only when the server said when it lifts. The per-network and 20-an-hour waits send
    // `details.retryAfterSeconds`; the 100-failure hard stop sends none and needs a password reset or another sign-in.
    @Test
    fun `ACCOUNT_LOCKED is retryable only with a wait`() = runBlocking {
        val rig = Rig()
        rig.transport.enqueue(
            "/auth-service/login",
            errorEnvelope("ACCOUNT_LOCKED", 403, details = mapOf("retryAfterSeconds" to 900)),
            errorEnvelope("ACCOUNT_LOCKED", 403),
        )
        val cooling = rig.auth.signIn("b@x.io", "pw").exceptionOrNull() as SendoraCloudAuthError
        assertEquals(SendoraCloudAuthErrorKind.ACCOUNT_LOCKED, cooling.kind)
        assertEquals(900, cooling.retryAfterSeconds)
        assertTrue("a cool-off lifts on its own", cooling.retryable)
        val hardStop = rig.auth.signIn("b@x.io", "pw").exceptionOrNull() as SendoraCloudAuthError
        assertEquals(SendoraCloudAuthErrorKind.ACCOUNT_LOCKED, hardStop.kind)
        assertNull(hardStop.retryAfterSeconds)
        assertFalse("the hard stop does not lift with time", hardStop.retryable)
    }

    @Test
    fun `the map keeps the newest 20 accounts`() {
        var entries = emptyList<KnownDeviceTokens.Entry>()
        for (i in 0 until 25) entries = KnownDeviceTokens.put(entries, "u$i@x.io", "t$i", now = i.toLong())
        assertEquals(20, entries.size)
        assertEquals("newest first", "t24", entries.first().token)
        assertNull("the oldest fell off", KnownDeviceTokens.lookup(entries, "u4@x.io"))
        assertEquals("t5", KnownDeviceTokens.lookup(entries, "u5@x.io"))
        entries = KnownDeviceTokens.put(entries, "U5@x.io", "t5b", now = 99)
        assertEquals("a re-sign-in moves the account to the front, once", listOf("t5b"), entries.filter { it.token.startsWith("t5") }.map { it.token })
        assertEquals("t5b", entries.first().token)
        assertEquals(entries, KnownDeviceTokens.decode(KnownDeviceTokens.encode(entries)))
        assertEquals(20, JSONArray(KnownDeviceTokens.encode(entries)).length())
    }

    // ─── cf-mitigated on auth calls (real ApiClient against a local server) ──

    private fun realAuth(http: TestHttpResponder, store: RecordingStore, events: MutableList<AuthStateChange>): SendoraCloudAuth =
        SendoraCloudAuth(
            client = ApiClient(http.baseUrl, "pk_test"),
            storage = store,
            onIdentityChange = {},
            onAnonymousWipe = {},
            cron = RecordingCron(),
            clock = { 1_760_000_000_000L },
            background = { block -> runBlocking { block() } },
            eventSink = { events += it },
        )

    @Test
    fun `an edge challenge on a refresh is never a dead session`() = runBlocking {
        TestHttpResponder().use { http ->
            // The body even carries the dead verdict's code: the backend never saw the request.
            http.answer(403, """{"success":false,"error":{"code":"INVALID_REFRESH_TOKEN","message":"m"}}""", "cf-mitigated" to "challenge")
            val store = RecordingStore()
            store.seedLegacySession(uB, jwt(uB.id, "sid-B", anonymous = false, exp = 1L), "rB", expiresAt = 1L) // access token expired
            val events = mutableListOf<AuthStateChange>()
            val auth = realAuth(http, store, events)
            auth.getAccessToken(forceRefresh = true)
            assertTrue("the refresh did go to the edge", http.paths.any { it.endsWith("/auth-service/token/refresh") })
            assertEquals("the refresh token is still on disk", "rB", store.secure[AuthKeys.REFRESH])
            assertNotEquals(AuthStatus.SIGNED_OUT, auth.status())
            assertTrue("no signed_out", events.none { it.event == "signed_out" })
        }
    }

    @Test
    fun `an edge challenge on a sign-in is a network failure that leaves the session as found`() = runBlocking {
        TestHttpResponder().use { http ->
            http.answer(403, "<html>challenge</html>", "cf-mitigated" to "challenge")
            val store = RecordingStore()
            store.seedLegacySession(uD, jwt(uD.id, "sid-D", anonymous = false), "rD", expiresAt = 2_000_000_000_000L)
            val auth = realAuth(http, store, mutableListOf())
            val err = auth.signIn("b@x.io", "pw").exceptionOrNull() as SendoraCloudAuthError
            assertEquals("retryable — never INVALID_CREDENTIAL", SendoraCloudAuthErrorKind.NETWORK, err.kind)
            assertEquals("rD", store.secure[AuthKeys.REFRESH])
            assertEquals(uD.id, auth.currentUser?.id)
        }
    }
}
