package com.sendoracloud.sdk

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `discardHeldGuest(id, keepSupportTickets = true)` (parity RN 1.45.0, server
 * s58.405-k): the body carries `keepSupportTickets: true` next to the GUEST's
 * refresh token, and the request carries the CURRENT account's access token as
 * `Authorization: Bearer`. Identified sessions only — anything else is refused
 * before a byte is sent. Slot rules are the plain discard's: 2xx / 404 release,
 * anything else keeps the slot. Asserted on what the stub transport SAW.
 */
class KeepTicketsDiscardTest {

    private val uA = user("aaaaaaaa-0000-4000-8000-000000000001", anonymous = true)
    private val uB = user("bbbbbbbb-0000-4000-8000-000000000002", anonymous = false, email = "b@x.io")
    private val path = "/auth-service/guest/discard"

    private fun rig(current: SendoraCloudAuthUser, refresh: String): Pair<Rig, String> {
        val store = RecordingStore()
        store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 1))
        val access = jwt(current.id, "sid-${current.id}", anonymous = current.isAnonymous)
        store.seedLegacySession(current, access, refresh, 2_000_000_000_000L)
        return Rig(store = store).also { it.transport.requests.clear() } to access
    }

    @Test
    fun `identified + keepSupportTickets sends the flag, the guest token and the account Bearer, then releases the slot`() = runBlocking {
        val (rig, accountAccess) = rig(uB, "rB")
        rig.transport.enqueue(path, okEnvelope(mapOf("userId" to "g1", "status" to "purged", "supportTicketsMoved" to 2)))
        rig.auth.discardHeldGuest("g1", keepSupportTickets = true).getOrThrow()

        val req = rig.transport.sent(path).single()
        assertEquals(mapOf("refreshToken" to "rG1", "keepSupportTickets" to true), req.body)
        val auth = req.headers?.get("Authorization")
        assertEquals("the CURRENT account's access token is the Bearer", "Bearer $accountAccess", auth)
        assertNotEquals("never the guest's token", "Bearer rG1", auth)
        assertNull("the held slot is released", rig.store.heldJson(0))
        assertTrue(rig.events.any { it is AuthStateChange.GuestReleased })
        assertEquals("the account session is untouched", AuthStatus.IDENTIFIED, rig.auth.status())
    }

    @Test
    fun `no id + keepSupportTickets resolves the single held guest`() = runBlocking {
        val (rig, _) = rig(uB, "rB")
        rig.transport.enqueue(path, okEnvelope(mapOf("userId" to "g1", "status" to "purged")))
        rig.auth.discardHeldGuest(keepSupportTickets = true).getOrThrow()
        assertEquals(true, rig.transport.sent(path).single().body!!["keepSupportTickets"])
        assertNull(rig.store.heldJson(0))
    }

    @Test
    fun `without the option the request is the plain discard - no flag, no Authorization`() = runBlocking {
        val (rig, _) = rig(uB, "rB")
        rig.transport.enqueue(path, okEnvelope(mapOf("userId" to "g1", "status" to "purged")), okEnvelope())
        rig.auth.discardHeldGuest("g1").getOrThrow()
        val req = rig.transport.sent(path).single()
        assertEquals(mapOf("refreshToken" to "rG1"), req.body)
        assertNull("no extra headers at all", req.headers)
        assertNull(rig.store.heldJson(0))

        // keepSupportTickets = false is the same request
        val (rig2, _) = rig(uB, "rB")
        rig2.transport.enqueue(path, okEnvelope(mapOf("userId" to "g1", "status" to "purged")))
        rig2.auth.discardHeldGuest("g1", keepSupportTickets = false).getOrThrow()
        val req2 = rig2.transport.sent(path).single()
        assertEquals(mapOf("refreshToken" to "rG1"), req2.body)
        assertNull(req2.headers)
    }

    @Test
    fun `anonymous session + keepSupportTickets is refused KEEP_TICKETS_REQUIRES_IDENTIFIED with nothing sent and the slot kept`() = runBlocking {
        val (rig, _) = rig(uA, "rA")
        val r = rig.auth.discardHeldGuest("g1", keepSupportTickets = true)
        val err = r.exceptionOrNull() as SendoraCloudAuthError
        assertEquals("KEEP_TICKETS_REQUIRES_IDENTIFIED", err.code)
        assertEquals(SendoraCloudAuthErrorKind.CONFIG, err.kind)
        assertFalse(err.retryable)
        assertEquals("zero requests", 0, rig.transport.requests.size)
        assertNotNull("the slot is kept", rig.store.heldJson(0))
    }

    @Test
    fun `signed out + keepSupportTickets is refused with nothing sent`() = runBlocking {
        val store = RecordingStore()
        store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 1))
        val rig = Rig(store = store).also { it.transport.requests.clear() }
        val err = rig.auth.discardHeldGuest("g1", keepSupportTickets = true).exceptionOrNull() as SendoraCloudAuthError
        assertEquals("KEEP_TICKETS_REQUIRES_IDENTIFIED", err.code)
        assertEquals(0, rig.transport.requests.size)
        assertNotNull(store.heldJson(0))
    }

    @Test
    fun `a server 422 fails the Result and keeps the slot`() = runBlocking {
        val (rig, _) = rig(uB, "rB")
        rig.transport.enqueue(path, errorEnvelope("VALIDATION_ERROR", 422, "keepSupportTickets needs an identified account"))
        val err = rig.auth.discardHeldGuest("g1", keepSupportTickets = true).exceptionOrNull() as SendoraCloudAuthError
        assertEquals("VALIDATION_ERROR", err.code)
        assertEquals(422, err.status)
        assertNotNull("the slot is kept", rig.store.heldJson(0))
        assertFalse(rig.events.any { it is AuthStateChange.GuestReleased })
    }

    @Test
    fun `a 404 (guest already gone) still releases the slot`() = runBlocking {
        val (rig, _) = rig(uB, "rB")
        rig.transport.enqueue(path, errorEnvelope("NOT_FOUND", 404))
        rig.auth.discardHeldGuest("g1", keepSupportTickets = true).getOrThrow()
        assertNull(rig.store.heldJson(0))
    }
}
