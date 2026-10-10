package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.AuthKeys
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ADR-033 wave 1 behavioural suites that sit BESIDE the fixture replay
 * (`AuthMachineConformanceTest`): the §5 items that are not one transition row
 * — INV-3 across every sign-in verb, `signUp` routing, the B15 pending hold
 * report, INV-9 slot dedupe, the B10 mint key, INV-14's bound `switchAccount`,
 * the deprecated aliases, integrator test 10, and the subscribe replay.
 * Everything is asserted on what the recording store / scripted transport SAW.
 */
class AuthMachineBehaviourTest {

    private val uA = user("aaaaaaaa-0000-4000-8000-000000000001", anonymous = true)
    private val uB = user("bbbbbbbb-0000-4000-8000-000000000002", anonymous = false, email = "b@x.io")
    private val uC = user("cccccccc-0000-4000-8000-000000000003", anonymous = true)
    private val uD = user("dddddddd-0000-4000-8000-000000000004", anonymous = false, email = "d@x.io")
    private val NO_HINT_FIELDS = setOf("prevAnonRefreshToken", "linkAnonymous", "onCredentialInUse")

    private fun rigWith(u: SendoraCloudAuthUser, refresh: String, store: RecordingStore = RecordingStore(), expectedProjectId: String? = null): Rig {
        store.seedLegacySession(u, jwt(u.id, "sid-${u.id}", anonymous = u.isAnonymous), refresh, 2_000_000_000_000L)
        return Rig(store = store, expectedProjectId = expectedProjectId).also { it.transport.requests.clear() }
    }

    // ─── lockstep ruling (1): the subscribe replay keeps the 4.25.0 SignedIn ──

    @Test
    fun `subscribe replays Initial and then the legacy SignedIn when a session exists`() {
        val rig = rigWith(uA, "rA")
        val seen = mutableListOf<AuthStateChange>()
        rig.auth.onAuthStateChanged { seen += it }
        assertEquals("Initial first, then the 4.25.0 SignedIn replay (removing it is an event removal)", listOf("initial", "signed_in"), seen.map { it.event })
        assertEquals(AuthStatus.ANONYMOUS, (seen[0] as AuthStateChange.Initial).status)
        assertEquals(uA, (seen[1] as AuthStateChange.SignedIn).user)
        assertNull("the replay carries no cause, exactly as 4.25.0 emitted it", (seen[1] as AuthStateChange.SignedIn).cause)
        // No session → Initial only (4.25.0 replayed nothing; Initial is the additive part).
        for ((status, r) in listOf(AuthStatus.SIGNED_OUT to Rig(), AuthStatus.WITHHELD to withheld())) {
            val s = mutableListOf<AuthStateChange>()
            r.auth.onAuthStateChanged { s += it }
            assertEquals(listOf("initial"), s.map { it.event })
            assertEquals(status, (s.single() as AuthStateChange.Initial).status)
        }
    }

    private fun withheld(): Rig {
        val store = RecordingStore()
        store.seedLegacySession(uA.copy(project = PROJECT_B), jwt(uA.id, "sid-A", project = PROJECT_B), "rA", 2_000_000_000_000L)
        return Rig(store = store, expectedProjectId = PROJECT_A)
    }

    // ─── the downgrade cycle: 4.26 → 4.25 → signOut/delete → 4.26 ──────────

    /** What a 4.25.0 signOut()/deleteAccount() does to the disk: the four frozen keys, nothing else. */
    private fun legacy425Clear(store: RecordingStore) {
        for (k in listOf(AuthKeys.ACCESS, AuthKeys.REFRESH, AuthKeys.EXPIRES, AuthKeys.USER)) store.secure.remove(k)
    }

    @Test
    fun `a leftover auth_session with no matching frozen refresh key is cleared silently, never reinstalled`() = runBlocking {
        // 4.26.0 signs a guest in → auth_session + the four frozen keys.
        val store = RecordingStore()
        val first = Rig(store = store)
        first.transport.enqueue("/auth-service/anonymous", sessionEnvelope(uA, jwt(uA.id, "sid-A"), "rA"))
        first.auth.signInAnonymously().getOrThrow()
        assertNotNull(store.secure[AuthKeys.SESSION])
        // Downgrade to 4.25.0, which signs out (or deletes): it clears ONLY the frozen keys.
        legacy425Clear(store)
        // Upgrade back to 4.26.0.
        val back = Rig(store = store)
        assertEquals("the signed-out account is NOT resurrected", AuthStatus.SIGNED_OUT, back.auth.status())
        assertNull(back.auth.currentUser)
        assertNull("the leftover record is cleared", store.secure[AuthKeys.SESSION])
        assertEquals("silently: no event", emptyList<String>(), back.eventNames)
        assertEquals("no network", 0, back.transport.requests.size)
        assertEquals("no cron", 0, back.cron.arms)

        // 4.25.0 signed in as SOMEONE ELSE under the record: the frozen keys are the truth.
        val s2 = RecordingStore()
        val r1 = Rig(store = s2)
        r1.transport.enqueue("/auth-service/anonymous", sessionEnvelope(uA, jwt(uA.id, "sid-A"), "rA"))
        r1.auth.signInAnonymously().getOrThrow()
        s2.seedLegacySession(uB, jwt(uB.id, "sid-B", anonymous = false), "rB", 2_000_000_000_000L)
        val r2 = Rig(store = s2)
        assertEquals(uB.id, r2.auth.currentUser?.id)
        assertEquals("rB", r2.auth.getRefreshToken())
        assertEquals("the record is re-written forward from the frozen keys", "rB", JSONObject(s2.secure[AuthKeys.SESSION] as String).getString("refreshToken"))
        assertEquals(emptyList<String>(), r2.eventNames)
    }

    @Test
    fun `every install writes the frozen keys BEFORE the record`() = runBlocking {
        val rig = Rig()
        rig.transport.enqueue("/auth-service/anonymous", sessionEnvelope(uA, jwt(uA.id, "sid-A"), "rA"))
        rig.auth.signInAnonymously().getOrThrow()
        val keys = rig.store.writes.filter { it.tier == "secure" }.map { it.key }
        val record = keys.indexOf(AuthKeys.SESSION)
        for (k in listOf(AuthKeys.ACCESS, AuthKeys.REFRESH, AuthKeys.EXPIRES, AuthKeys.USER)) {
            assertTrue("$k written before auth_session ($keys)", keys.indexOf(k) in 0 until record)
        }
    }

    // ─── INV-3: no sign-in request carries a guest hint ─────────────────────

    @Test
    fun `every sign-in verb from a guest sends NO guest hint and HOLDS the guest`() = runBlocking {
        val verbs: List<Pair<String, suspend (SendoraCloudAuth) -> Result<*>>> = listOf(
            "/auth-service/login" to { a -> a.signIn("b@x.io", "pw") },
            "/auth-service/login/social" to { a -> a.loginSocial("google", idToken = "id") },
            "/auth-service/login/social" to { a -> a.signInWithGoogle("code", "app://cb") },
            "/auth-service/login/play-games" to { a -> a.signInWithPlayGames("pg-code") },
            "/auth-service/magic-link/verify" to { a -> a.verifyMagicLink("ml") },
            "/auth-service/email-otp/verify" to { a -> a.verifyEmailOtp("b@x.io", "123456") },
            "/auth-service/mfa/challenge" to { a -> a.challengeMfa("ch", "123456") },
            "/auth-service/login/play-games" to { a -> a.signInWith(Credential.PlayGames("pg", "p1")) },
        )
        for ((path, call) in verbs) {
            val rig = rigWith(uA, "rA")
            rig.transport.enqueue(path, sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB"))
            assertTrue("$path succeeded", call(rig.auth).isSuccess)
            val body = rig.transport.sent(path).single().body!!
            assertTrue("$path body carries no guest hint: ${body.keys}", body.keys.none { it in NO_HINT_FIELDS })
            assertTrue("$path never presents the guest's refresh token", body.values.none { it == "rA" })
            assertEquals("$path: guest held", uA.id, rig.auth.heldGuests().single().userId)
            assertEquals(listOf("guest_held", "signed_in"), rig.eventNames)
            assertTrue("no signed_out on replace", rig.eventNames.none { it == "signed_out" })
        }
    }

    // ─── signUp routes by status, never /upgrade ────────────────────────────

    @Test
    fun `signUp routes by status and never calls upgrade`() = runBlocking {
        val out = Rig()
        out.transport.enqueue("/auth-service/signup", sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB"))
        assertEquals(uB.id, out.auth.signUp("b@x.io", "pw").getOrThrow().id)
        assertEquals(listOf("/auth-service/signup"), out.transport.requests.map { it.path })

        val identified = rigWith(uB, "rB")
        val mark = identified.store.writes.size
        assertTrue(identified.auth.signUp("x@x.io", "pw").exceptionOrNull() is SendoraCloudAuthError.AlreadyIdentified)
        assertEquals("AlreadyIdentified is LOCAL — no round-trip", 0, identified.transport.requests.size)
        assertEquals(mark, identified.store.writes.size)

        // withheld: SESSION_WITHHELD, no network, no write (the "signUp reads REFRESH_KEY in withheld" mutation)
        val w = withheld()
        val r = w.auth.signUp("x@x.io", "pw")
        assertEquals("SESSION_WITHHELD", (r.exceptionOrNull() as SendoraCloudAuthError).code)
        assertEquals(0, w.transport.requests.size); assertEquals(emptyList<StoreWrite>(), w.store.writes)

        for (rig in listOf(out, identified, w)) assertEquals(0, rig.transport.count("/auth-service/upgrade"))
    }

    // ─── B15: the hold report is retried on hydrate until it lands ──────────

    @Test
    fun `a failed hold report is persisted as pending and retried on the next hydrate`() = runBlocking {
        val rig = rigWith(uA, "rA")
        rig.transport.on("/auth-service/guest/held") { null } // offline
        rig.transport.enqueue("/auth-service/login", sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB"))
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        assertEquals(1, rig.transport.count("/auth-service/guest/held"))
        val pending = JSONObject(rig.store.secure[AuthKeys.SESSION] as String).getJSONArray("heldReportPending")
        assertEquals("the pending flag is non-secret and lives in auth_session", uA.id, pending.getString(0))

        // Next boot, still offline: retried, still pending.
        val next = Rig(store = rig.store)
        assertEquals("retried on hydrate", 1, next.transport.count("/auth-service/guest/held"))
        assertEquals(1, JSONObject(next.store.secure[AuthKeys.SESSION] as String).getJSONArray("heldReportPending").length())
        // Next boot, online: retried and cleared.
        val again = Rig(store = rig.store, transport = StubTransport().also { t -> t.on("/auth-service/guest/held") { okEnvelope(mapOf("reported" to true)) } })
        assertEquals("rA", again.transport.sent("/auth-service/guest/held").single().body!!["refreshToken"])
        assertEquals("cleared once reported", 0, JSONObject(again.store.secure[AuthKeys.SESSION] as String).getJSONArray("heldReportPending").length())
        val third = Rig(store = again.store)
        assertEquals("not re-sent after success", 0, third.transport.count("/auth-service/guest/held"))
    }

    // ─── INV-9: a held slot holding the CURRENT user is dropped at hydrate ───

    @Test
    fun `hydrate drops a held slot that duplicates the current user`() {
        val store = RecordingStore()
        store.seedHeld(2, heldSlotJson(uA.id, "rOld", heldAt = 5))
        store.seedHeld(3, heldSlotJson("other", "rO", heldAt = 6))
        val rig = rigWith(uA, "rA", store = store)
        assertEquals("current wins", listOf("other"), rig.auth.heldGuests().map { it.userId })
        assertNull(store.secure[AuthKeys.HELD_SLOT_KEYS[2]])
        assertEquals("silently — a dedupe is not a release the app made", emptyList<String>(), rig.eventNames)
    }

    // ─── B10: the mint key survives a failed attempt, dies with MINT_OK ─────

    @Test
    fun `the per-attempt mintKey is re-presented after a failed attempt and dropped on success`() = runBlocking {
        val rig = Rig()
        rig.transport.enqueue("/auth-service/anonymous", null)
        assertTrue(rig.auth.signInAnonymously().isFailure)
        val key = rig.store.plain[AuthKeys.MINT_KEY] as String
        assertEquals(key, rig.transport.sent("/auth-service/anonymous").single().body!!["mintKey"])
        // "process death": a new machine over the same disk
        val next = Rig(store = rig.store)
        next.transport.enqueue("/auth-service/anonymous", sessionEnvelope(uA, jwt(uA.id, "sid-A"), "rA"))
        next.auth.signInAnonymously().getOrThrow()
        assertEquals("the retry presents the SAME key (same guest back)", key, next.transport.sent("/auth-service/anonymous").single().body!!["mintKey"])
        assertNull("dropped on MINT_OK", next.store.plain[AuthKeys.MINT_KEY])
    }

    // ─── INV-14: switchAccount is BOUND to the refused credential ───────────

    @Test
    fun `switchAccount re-presents a fresh payload and compares a re-fetched one`() = runBlocking {
        fun refused(rig: Rig): LinkResult.CredentialInUse = runBlocking {
            rig.transport.enqueue("/auth-service/me/link/play-games", errorEnvelope("CREDENTIAL_IN_USE", 409, details = mapOf("provider" to "playgames", "collision" to "identity")))
            rig.auth.link(Credential.PlayGames("code-1", playerId = "p1")).getOrThrow() as LinkResult.CredentialInUse
        }
        // < 5 min: the same payload
        val fresh = rigWith(uA, "rA")
        val cu = refused(fresh)
        fresh.transport.enqueue("/auth-service/login/play-games", sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB"))
        val done = cu.switchAccount().getOrThrow() as SignInResult.Done
        assertEquals("code-1", fresh.transport.sent("/auth-service/login/play-games").single().body!!["serverAuthCode"])
        assertEquals(PreviousSession(uA.id, isAnonymous = true, held = true), done.previous)

        // ≥ 5 min, no refetch → credential_changed, nothing sent
        val stale = rigWith(uA, "rA")
        val cu2 = refused(stale)
        stale.now += 6 * 60_000L
        assertTrue(cu2.switchAccount().exceptionOrNull() is SendoraCloudAuthError.CredentialChanged)
        assertEquals(0, stale.transport.count("/auth-service/login/play-games"))
        // ≥ 5 min, a re-fetched credential naming ANOTHER player → credential_changed
        assertTrue(cu2.switchAccount { Credential.PlayGames("code-2", playerId = "p2") }.exceptionOrNull() is SendoraCloudAuthError.CredentialChanged)
        assertEquals(0, stale.transport.count("/auth-service/login/play-games"))
        // ≥ 5 min, the SAME player re-fetched → signs in with the NEW code
        stale.transport.enqueue("/auth-service/login/play-games", sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB"))
        assertTrue(cu2.switchAccount { Credential.PlayGames("code-3", playerId = "p1") }.isSuccess)
        assertEquals("code-3", stale.transport.sent("/auth-service/login/play-games").single().body!!["serverAuthCode"])
        // keepCurrent is a no-op on state
        val keep = rigWith(uA, "rA"); refused(keep).keepCurrent()
        assertEquals(AuthStatus.ANONYMOUS, keep.auth.status())
    }

    // ─── (f) deprecated aliases ─────────────────────────────────────────────

    @Test
    @Suppress("DEPRECATION")
    fun `deprecated merge routes a journalled token to its held slot, else to raw merge`() = runBlocking {
        val store = RecordingStore()
        store.seedHeld(0, heldSlotJson(uA.id, "rA-now", heldAt = 1, tokenAtHold = "rA-journalled"))
        val rig = rigWith(uB, "rB", store = store)
        rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(uA, jwt(uA.id, "sid-A"), "rA-next"))
        rig.transport.enqueue("/auth-service/merge", okEnvelope(mapOf("mergedUserId" to uB.id, "deletedAnonymousId" to uA.id, "tokens" to mapOf("accessToken" to jwt(uB.id, "sid-B", anonymous = false), "refreshToken" to "rB2", "expiresIn" to 900))))
        rig.auth.merge("rA-journalled").getOrThrow()
        assertEquals("the held token is refreshed first", "rA-now", rig.transport.sent("/auth-service/token/refresh").single().body!!["refreshToken"])
        assertEquals("rA-next", rig.transport.sent("/auth-service/merge").single().body!!["anonRefreshToken"])
        assertEquals(0, rig.auth.heldGuests().size)
        assertTrue(rig.eventNames.contains("guest_released"))
        // A token no slot knows → raw /merge, no refresh
        rig.transport.enqueue("/auth-service/merge", okEnvelope(mapOf("mergedUserId" to uB.id, "tokens" to mapOf("accessToken" to jwt(uB.id, "sid-B", anonymous = false), "refreshToken" to "rB3", "expiresIn" to 900))))
        rig.auth.merge("rX").getOrThrow()
        assertEquals("rX", rig.transport.sent("/auth-service/merge").last().body!!["anonRefreshToken"])
        assertEquals(1, rig.transport.count("/auth-service/token/refresh"))
        assertEquals("rB3", rig.auth.getRefreshToken())
    }

    @Test
    fun `device takeover fires only on a server-reported retirement`() = runBlocking {
        val retired = "eeeeeeee-0000-4000-8000-000000000005"
        val quiet = rigWith(uA, "rA")
        var fired = 0
        quiet.auth.onDeviceTakeover { fired++ }
        quiet.transport.enqueue("/auth-service/login", sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB", extra = mapOf("anonRetirement" to "none")))
        quiet.auth.signIn("b@x.io", "pw").getOrThrow()
        assertEquals("a 4.26.0 sign-in retires nothing", 0, fired)
        assertNull(quiet.auth.getLastDeviceTakeover())
        assertEquals(AnonRetirementOutcome.NONE, quiet.auth.getLastAnonRetirement())

        val legacy = rigWith(uA, "rA")
        var evt: DeviceTakeoverEvent? = null
        legacy.auth.onDeviceTakeover { evt = it }
        legacy.transport.enqueue("/auth-service/login", sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB", extra = mapOf("retiredAnonUserId" to retired)))
        legacy.auth.signIn("b@x.io", "pw").getOrThrow()
        assertEquals(retired, evt?.retiredAnonUserId)
        assertTrue(legacy.eventNames.contains("device_takeover"))
    }

    // ─── heldAt is strictly increasing (lockstep: no same-millisecond tie) ──

    @Test
    fun `two holds at a frozen clock are strictly ordered and the newer one is auto-restored`() = runBlocking {
        val rig = rigWith(uA, "rA") // rig.now never moves in this test
        rig.transport.enqueue("/auth-service/login", sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB"))
        rig.auth.signIn("b@x.io", "pw").getOrThrow()                     // hold A at t
        rig.transport.enqueue("/auth-service/anonymous", sessionEnvelope(uC, jwt(uC.id, "sid-C"), "rC"))
        rig.auth.signInAnonymously(forceNew = true).getOrThrow()
        rig.transport.enqueue("/auth-service/login", sessionEnvelope(uD, jwt(uD.id, "sid-D", anonymous = false), "rD"))
        rig.auth.signIn("d@x.io", "pw").getOrThrow()                     // hold C — same millisecond
        val held = rig.auth.getHeldGuests()
        assertEquals(listOf(uC.id, uA.id), held.map { it.userId })
        assertTrue("strictly greater, never a tie: ${held.map { it.heldAt }}", held[0].heldAt > held[1].heldAt)
        assertEquals(rig.now, held[1].heldAt)
        // "newest" is therefore defined: a plain mint from signed_out restores C, not A.
        rig.auth.signOut()
        rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(uC, jwt(uC.id, "sid-C"), "rC2"))
        assertEquals(uC.id, rig.auth.ensureSession().getOrThrow().id)
    }

    // ─── integrator test 10 ─────────────────────────────────────────────────

    @Test
    fun `two sign-ins from two different guests hold both, count 1 then 2, newest first`() = runBlocking {
        val rig = rigWith(uA, "rA")
        rig.transport.enqueue("/auth-service/login", sessionEnvelope(uB, jwt(uB.id, "sid-B", anonymous = false), "rB"))
        rig.auth.signIn("b@x.io", "pw").getOrThrow()
        rig.now += 1_000
        rig.transport.enqueue("/auth-service/anonymous", sessionEnvelope(uC, jwt(uC.id, "sid-C"), "rC"))
        assertEquals(uC.id, rig.auth.signInAnonymously(forceNew = true).getOrThrow().id)
        rig.now += 1_000
        rig.transport.enqueue("/auth-service/login", sessionEnvelope(uD, jwt(uD.id, "sid-D", anonymous = false), "rD"))
        rig.auth.signIn("d@x.io", "pw").getOrThrow()
        val held = rig.events.filterIsInstance<AuthStateChange.GuestHeld>()
        assertEquals(listOf(uA.id to 1, uC.id to 2), held.map { it.userId to it.count })
        assertEquals("heldAt desc", listOf(uC.id, uA.id), rig.auth.getHeldGuests().map { it.userId })
        assertNotNull(rig.store.secure[AuthKeys.HELD_SLOT_KEYS[0]]); assertNotNull(rig.store.secure[AuthKeys.HELD_SLOT_KEYS[1]])
        assertTrue("nothing displaced", rig.eventNames.none { it == "guest_released" })
    }
}
