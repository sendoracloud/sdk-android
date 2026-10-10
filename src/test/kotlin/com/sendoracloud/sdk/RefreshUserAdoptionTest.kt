package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.AuthKeys
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The other half of the corrupt-cache guard — now driven BEHAVIOURALLY.
 *
 * The constructor KEEPS the stored refresh token when the cached `auth_user`
 * blob is unreadable: it is independently valid and the only thing that can
 * still recover the account. `/token/refresh` returns the user in the same
 * response, and the refresh path adopts it (the gap-fill that settles
 * `UNKNOWN`, ADR-033 §3.3 row 3 / row 20).
 *
 * ⚠ PINS CONVERTED (4.26.0, ADR-033 wave 1). Until 4.25.0 these four tests read
 * `SendoraCloudAuth.kt` as TEXT (`storage.clearCachedUser()`,
 * `if (cachedUser == null)`, `parseLinkedUser(response)?.let`, one
 * `emitAuthState(` in `refreshAccessToken`) because driving the refresh path
 * needed a `Context`-backed `Storage`. Wave 1 put the machine behind the
 * `AuthStore` / `AuthTransport` seams, so each pin is now the behaviour it was
 * standing in for, asserted on a recording store and a scripted transport.
 * A source-text pin proves "token present", never "behaves" (the s58.333
 * guard asserted the very bug it was meant to catch). One property CHANGED on
 * purpose and is converted, not kept: "a live user is never overwritten by a
 * rotation" is superseded by the shared fixture row `refresh_ok.current_match`
 * — a refresh whose user object DIFFERS installs it and emits
 * `UserUpdated(REFRESH)` (RN reference parity); a refresh that carries NO user
 * still leaves the live user untouched.
 */
class RefreshUserAdoptionTest {

    private val u = user("aaaaaaaa-0000-4000-8000-000000000001", anonymous = true)
    private fun tok() = jwt(u.id, "sid-A")

    /** LIMBO_A: a refresh token on disk, an unreadable user blob. */
    private fun limbo(): Rig {
        val store = RecordingStore()
        store.secure[AuthKeys.REFRESH] = "rA"
        store.secure[AuthKeys.ACCESS] = tok()
        store.secure[AuthKeys.USER] = "{corrupt"
        return Rig(store = store)
    }

    @Test
    fun `the corrupt-cache guard keeps the refresh token`() {
        val rig = limbo()
        assertEquals("an unreadable user is UNKNOWN, never signed_out", AuthStatus.UNKNOWN, rig.auth.status())
        assertEquals("the refresh token survives the boot", "rA", rig.store.secure[AuthKeys.REFRESH])
        assertTrue("no path in the constructor writes the refresh key", rig.store.writesTo(AuthKeys.REFRESH).isEmpty())
        assertEquals("boot with an unsettled record writes nothing at all", emptyList<StoreWrite>(), rig.store.writes)
        assertNull("no user is invented", rig.auth.currentUser)
        assertEquals("the gap-fill cron is armed", 1, rig.cron.arms)
    }

    @Test
    fun `refresh adopts the returned user when there is none, and only a well-formed one`() = runBlocking {
        val rig = limbo()
        rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(u, tok(), "rA2"))
        rig.auth.getAccessToken()
        assertEquals(u.id, rig.auth.currentUser?.id)
        assertEquals(AuthStatus.ANONYMOUS, rig.auth.status())
        assertEquals("the adopted user is persisted like a sign-in's", u.id, AuthCodecsProbe.userIdOf(rig.store.secure[AuthKeys.USER] as String))
        assertEquals(listOf(u.id), rig.identityChanges)

        // A malformed user (empty id) is NOT adopted: the record stays UNKNOWN.
        val bad = limbo()
        bad.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(u.copy(id = ""), tok(), "rA2"))
        bad.auth.getAccessToken()
        assertEquals(AuthStatus.UNKNOWN, bad.auth.status())
        assertNull(bad.auth.currentUser)

        // A live session whose refresh carries NO user keeps its user (rotation only).
        val store = RecordingStore(); store.seedLegacySession(u, tok(), "rA", 2_000_000_000_000L)
        val live = Rig(store = store)
        live.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(null, tok(), "rA2"))
        live.auth.getAccessToken(forceRefresh = true)
        assertEquals(u, live.auth.currentUser)
        assertEquals("rA2", live.auth.getRefreshToken())
    }

    @Test
    fun `adoption lands with the rotated tokens and never after the session was replaced`() = runBlocking {
        val rig = limbo()
        rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(u, tok(), "rA2"))
        rig.auth.getAccessToken()
        assertEquals("the rotated refresh token is stored", "rA2", rig.store.secure[AuthKeys.REFRESH])
        val userWrite = rig.store.writes.indexOfFirst { it.key == AuthKeys.USER }
        val refreshWrite = rig.store.writes.indexOfFirst { it.key == AuthKeys.REFRESH && it.value == "rA2" }
        assertTrue("the user is adopted in the same commit as the rotation", userWrite >= 0 && refreshWrite >= 0)

        // The in-flight-replacement guard: a gap-fill that lands after signOut adopts nothing.
        val raced = limbo()
        val gate = Gate()
        raced.transport.on("/auth-service/token/refresh") { gate.await(); refreshEnvelope(u, tok(), "rA2") }
        val refresh = async(Dispatchers.Default) { raced.auth.getAccessToken() }
        withTimeout(5_000) { gate.opened.await() }
        raced.auth.signOut()
        val mark = raced.store.writes.size
        gate.release()
        assertNull(withTimeout(5_000) { refresh.await() })
        assertEquals("nothing installed after the session it belonged to was cleared", mark, raced.store.writes.size)
        assertNull(raced.auth.currentUser)
        assertEquals(AuthStatus.SIGNED_OUT, raced.auth.status())
    }

    @Test
    fun `a recovered identity emits SignedIn and a plain rotation emits nothing`() = runBlocking {
        val rig = limbo()
        rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(u, tok(), "rA2"))
        rig.auth.getAccessToken()
        assertEquals("recovering an identity is a state transition and must reach listeners", listOf("signed_in"), rig.eventNames)
        assertEquals(u, (rig.events.single() as AuthStateChange.SignedIn).user)

        val store = RecordingStore(); store.seedLegacySession(u, tok(), "rA", 2_000_000_000_000L)
        val live = Rig(store = store)
        live.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(u, tok(), "rA2"))
        live.auth.getAccessToken(forceRefresh = true)
        assertEquals("a rotation with the same user is not a transition", emptyList<String>(), live.eventNames)
    }
}

/** Reads the `id` out of the frozen `auth_user` blob without the SDK's codec (an independent decoder). */
internal object AuthCodecsProbe {
    fun userIdOf(raw: String): String = org.json.JSONObject(raw).getString("id")
}
