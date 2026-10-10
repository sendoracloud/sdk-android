package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.AuthKeys
import com.sendoracloud.sdk.internal.AuthMachineSets
import com.sendoracloud.sdk.internal.PROJECT_CLAIM
import com.sendoracloud.sdk.internal.ProjectVerdict
import com.sendoracloud.sdk.internal.projectVerdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ADR-033 INV-11 — "one table, four ports": this suite REPLAYS
 * `packages/shared/src/auth-machine/auth-transitions.conformance.json` against
 * the Kotlin machine. The fixture is located by walking up from the module
 * directory and is never copied (a copy drifts).
 *
 * For EVERY transition row there is a scenario below, keyed by the row's stable
 * `id`, that builds the machine in the row's `from` state with a recording
 * store + a scripted transport, fires the row's event through the PUBLIC verbs,
 * and asserts the resulting status, the emitted events (wire names, in order)
 * and the writes / no-writes the row prescribes. A fixture row with no scenario
 * fails the suite (totality, both directions), so a row added in
 * `packages/shared` turns this suite red until the port catches up — which is
 * the point of INV-11.
 *
 * Every `projectVerdictCases` entry drives the ported `projectVerdict()` with
 * the fixture's LITERAL JWT, and — when its `context` is not `verdict` — the
 * install path it names (hydrate / mint / restore).
 */
class AuthMachineConformanceTest {

    private val fixture: JSONObject by lazy {
        val f = repoFile("packages/shared/src/auth-machine/auth-transitions.conformance.json")
            ?: error("auth-transitions.conformance.json not found above ${System.getProperty("user.dir")} — the shared fixture is the spec; do not copy it")
        JSONObject(f.readText())
    }

    private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
    private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }

    // ─── vocabularies ──────────────────────────────────────────────────────

    @Test
    fun `the closed vocabularies match the fixture`() {
        assertEquals(fixture.getJSONArray("states").strings(), AuthStatus.entries.map { it.wire })
        assertEquals(fixture.getInt("heldGuestSlots"), AuthKeys.HELD_SLOT_KEYS.size)
        assertEquals("the K slot names are the fixture's LITERAL names", fixture.getJSONArray("heldSlotKeys").strings(), AuthKeys.HELD_SLOT_KEYS)
        assertEquals(
            "the secure key set is EXACTLY the four frozen keys + auth_session + the fixture slots",
            (listOf("auth_access_token", "auth_refresh_token", "auth_access_expires", "auth_user", "auth_session") + fixture.getJSONArray("heldSlotKeys").strings()).toSet(),
            AuthKeys.SECURE_KEYS.toSet(),
        )
        assertEquals("the SDK's DEAD_CODES equal the fixture's", fixture.getJSONArray("deadCodes").strings().toSet(), AuthMachineSets.DEAD_CODES)
        assertEquals("the SDK's release set equals the fixture's", fixture.getJSONArray("releaseHeldOnEndReasons").strings().toSet(), AuthMachineSets.RELEASE_HELD_ON_END_REASONS)
        assertEquals(fixture.getJSONArray("rejectedInWithheld").strings().toSet(), REJECTED_IN_WITHHELD_DRIVERS.keys)
        assertEquals(fixture.getJSONArray("acceptedInWithheld").strings().toSet(), setOf("HYDRATE", "DISCARD_WITHHELD", "SIGN_OUT"))
        assertEquals("the guard reads the fixture's claim name", fixture.getString("projectClaim"), PROJECT_CLAIM)
        assertEquals(fixture.getJSONArray("events").strings().size, 15)
    }

    @Test
    fun `the dead-code and release sets are enforced by behaviour, not only declared`() = runBlocking {
        // A refresh refused with a NON-dead code keeps the session (INV-6)…
        for (code in listOf("UNAUTHORIZED", "HTTP_401", "RATE_LIMIT_EXCEEDED", "INTERNAL")) {
            val rig = anonymousRig()
            rig.transport.enqueue("/auth-service/token/refresh", errorEnvelope(code, if (code == "RATE_LIMIT_EXCEEDED") 429 else 401))
            rig.auth.getAccessToken(forceRefresh = true)
            assertEquals("$code must not end the session", AuthStatus.ANONYMOUS, rig.auth.status())
        }
        // …and ONLY deleted|revoked|expired release a held slot.
        for (reason in listOf("deleted", "revoked", "expired", "reuse", "unknown", null)) {
            val rig = signedOutRig()
            rig.store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
            val r = Rig(store = rig.store)
            r.transport.enqueue("/auth-service/token/refresh", deadRefresh(reason))
            r.auth.restoreHeldGuest("g1")
            val released = fixture.getJSONArray("releaseHeldOnEndReasons").strings().contains(reason)
            assertEquals("endReason=$reason releases=$released", released, r.store.secure[AuthKeys.HELD_SLOT_KEYS[0]] == null)
        }
    }

    // ─── the transition rows ───────────────────────────────────────────────

    @Test
    fun `every transition row replays and every scenario names a row`() {
        val rows = fixture.getJSONArray("transitions").objects()
        val ids = rows.map { it.getString("id") }
        assertEquals("fixture ids are unique", ids.size, ids.toSet().size)
        val missing = ids.filter { it !in SCENARIOS }
        assertEquals("fixture rows with NO Kotlin scenario (a new ADR row must be ported before this suite is green)", emptyList<String>(), missing)
        val orphan = SCENARIOS.keys.filter { it !in ids }
        assertEquals("scenarios naming a row the fixture no longer has", emptyList<String>(), orphan)
        val failures = mutableListOf<String>()
        for (row in rows) {
            val id = row.getString("id")
            try {
                SCENARIOS.getValue(id).invoke(row)
            } catch (t: Throwable) {
                failures += "$id: ${t.message ?: t.javaClass.simpleName}"
            }
        }
        assertEquals("rows that failed to replay:\n  " + failures.joinToString("\n  "), 0, failures.size)
        assertEquals(36, rows.size)
    }

    @Test
    fun `unspecified pairs are neither covered nor invented`() {
        val unspecified = fixture.getJSONArray("unspecifiedByAdr").objects().map { it.getString("from") to it.getString("event") }
        assertEquals(9, unspecified.size)
        // Each listed pair is a gap in the ADR; the port must not pretend a row exists for it.
        assertTrue(unspecified.none { (from, event) -> SCENARIOS.keys.any { it.startsWith("$from|$event") } })
    }

    // ─── projectVerdict cases ──────────────────────────────────────────────

    @Test
    fun `every projectVerdict case holds for the port and for the install path it names`() {
        val cases = fixture.getJSONArray("projectVerdictCases").objects()
        assertEquals(19, cases.size)
        val failures = mutableListOf<String>()
        for (c in cases) {
            val id = c.getString("id")
            try {
                val expected = if (c.isNull("expectedProjectId")) null else c.getString("expectedProjectId")
                val token = if (c.isNull("accessToken")) null else c.getString("accessToken")
                val verdict = ProjectVerdict.entries.first { it.wire == c.getString("verdict") }
                assertEquals("$id verdict", verdict, projectVerdict(expected, token))
                when (c.getString("context")) {
                    "verdict" -> Unit
                    "hydrate" -> verdictHydrate(c, expected!!, token!!)
                    "mint" -> verdictMint(c, expected!!, token!!)
                    "restore" -> verdictRestore(c, expected!!, token!!)
                    else -> fail("unknown context in $id")
                }
            } catch (t: Throwable) {
                failures += "$id: ${t.message ?: t.javaClass.simpleName}"
            }
        }
        assertEquals("verdict cases that failed:\n  " + failures.joinToString("\n  "), 0, failures.size)
    }

    private fun verdictHydrate(c: JSONObject, expected: String, token: String) {
        val store = RecordingStore()
        val u = user("9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a", anonymous = true, project = null).copy(projectKnown = false)
        store.seedLegacySession(u, token, "rt-stored", expiresAt = 2_000_000_000_000L)
        store.seedHeld(0, heldSlotJson("g-held", "rG", heldAt = 5))
        val before = store.snapshot()
        val rig = Rig(store = store, expectedProjectId = expected)
        assertEquals(c.getString("row"), when (c.getString("verdict")) { "mismatch" -> "hydrate.project_mismatch"; else -> "hydrate.gap_fill" })
        assertEquals("zero storage writes", emptyList<StoreWrite>(), store.writes)
        assertEquals("byte-identical disk", before, store.snapshot())
        if (c.getString("verdict") == "mismatch") {
            assertEquals(AuthStatus.WITHHELD, rig.auth.status())
            assertEquals(c.getString("errorCode"), "SESSION_WITHHELD")
            assertNotNull(rig.auth.withheld())
            assertEquals(1, rig.auth.heldGuests().size)
            runBlocking { assertEquals("SESSION_WITHHELD", rig.auth.signInAnonymously().exceptionOrNull()?.let { (it as SendoraCloudAuthError).code }) }
        } else {
            assertEquals(AuthStatus.UNKNOWN, rig.auth.status())
            assertEquals("the gap-fill cron is armed", 1, rig.cron.arms)
            assertEquals("never a mint", 0, rig.transport.count("/auth-service/anonymous"))
        }
    }

    private fun verdictMint(c: JSONObject, expected: String, token: String) = runBlocking {
        val rig = signedOutRig(expectedProjectId = expected)
        val minted = user("9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a", anonymous = true, project = PROJECT_B)
        rig.transport.enqueue("/auth-service/anonymous", sessionEnvelope(minted, token, "rt-minted"))
        val mark = rig.store.writes.size
        val r = rig.auth.signInAnonymously()
        val err = r.exceptionOrNull() as SendoraCloudAuthError
        assertEquals(c.getString("errorCode"), err.code)
        assertEquals(SendoraCloudAuthErrorKind.CONFIG, err.kind)
        assertEquals("status stays signed_out", AuthStatus.SIGNED_OUT, rig.auth.status())
        assertEquals("the minted refresh is revoked", "rt-minted", rig.transport.sent("/auth-service/token/revoke").single().body!!["refreshToken"])
        assertTrue("nothing installed", rig.writesSince(mark).none { it.key in AuthKeys.SECURE_KEYS })
        assertEquals(listOf<String>(), rig.eventNames)
        assertEquals(c.getString("row"), "mint.fresh")
    }

    private fun verdictRestore(c: JSONObject, expected: String, token: String) = runBlocking {
        val slotProject = if (c.isNull("slotProject")) null else c.getString("slotProject")
        val rig = signedOutRig(expectedProjectId = expected)
        rig.store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10, project = slotProject))
        val r = Rig(store = rig.store, expectedProjectId = expected)
        r.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(user("g1", true, project = PROJECT_A), token, "rG1'"))
        val result = r.auth.restoreHeldGuest("g1")
        assertEquals(c.getString("row"), "restore.held_guest")
        if (c.getString("verdict") == "mismatch") {
            val err = result.exceptionOrNull() as SendoraCloudAuthError
            assertEquals("HELD_GUEST_PROJECT_MISMATCH", err.code)
            assertTrue(err is SendoraCloudAuthError.HeldGuestProjectMismatch)
            assertEquals("refused CLIENT-SIDE before any network", 0, r.transport.requests.size)
            assertNotNull("slot KEPT", r.store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
            assertEquals(AuthStatus.SIGNED_OUT, r.auth.status())
            assertTrue("still counts toward T but is excluded from auto-restore", r.auth.heldGuests().size == 1)
            r.transport.enqueue("/auth-service/anonymous", sessionEnvelope(user("fresh", true), jwt("fresh", "sid-f"), "rF"))
            r.auth.signInAnonymously()
            assertEquals("auto-restore skipped the mismatching slot and minted", 1, r.transport.count("/auth-service/anonymous"))
        } else {
            assertTrue(result.isSuccess)
            assertEquals("g1", r.auth.currentUser?.id)
            assertNull("slot released", r.store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
        }
    }

    // ─── rigs ──────────────────────────────────────────────────────────────

    private val uA = user("aaaaaaaa-0000-4000-8000-000000000001", anonymous = true)
    private val uB = user("bbbbbbbb-0000-4000-8000-000000000002", anonymous = false, email = "b@x.io")
    private val uC = user("cccccccc-0000-4000-8000-000000000003", anonymous = false, email = "c@x.io")
    private fun tokA(sid: String = "sid-A") = jwt(uA.id, sid, anonymous = true)
    private fun tokB(sid: String = "sid-B") = jwt(uB.id, sid, anonymous = false)

    private fun anonymousRig(expectedProjectId: String? = null, store: RecordingStore = RecordingStore()): Rig {
        store.seedLegacySession(uA, tokA(), "rA", expiresAt = 2_000_000_000_000L)
        return Rig(store = store, expectedProjectId = expectedProjectId).also { it.store.writes.clear(); it.transport.requests.clear() }
    }

    private fun identifiedRig(expectedProjectId: String? = null, store: RecordingStore = RecordingStore()): Rig {
        store.seedLegacySession(uB, tokB(), "rB", expiresAt = 2_000_000_000_000L)
        return Rig(store = store, expectedProjectId = expectedProjectId).also { it.store.writes.clear() }
    }

    private fun signedOutRig(expectedProjectId: String? = null, autoRestore: Boolean = true, store: RecordingStore = RecordingStore()): Rig =
        Rig(store = store, expectedProjectId = expectedProjectId, autoRestoreHeldGuest = autoRestore)

    /** LIMBO_A: a refresh token on disk, no readable user. */
    private fun limboRig(withHeldG1: Boolean = false): Rig {
        val store = RecordingStore()
        store.secure[AuthKeys.REFRESH] = "rA"
        store.secure[AuthKeys.USER] = "{not json"
        // Seeded BEFORE the constructor: hydrate is the only reader of the held slots.
        if (withHeldG1) store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
        return Rig(store = store)
    }

    private fun withheldRig(): Rig {
        val store = RecordingStore()
        store.seedLegacySession(uA.copy(project = PROJECT_B), jwt(uA.id, "sid-A", project = PROJECT_B), "rA", expiresAt = 2_000_000_000_000L)
        store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
        return Rig(store = store, expectedProjectId = PROJECT_A)
    }

    /** The event wire names a fixture row's `emits` prescribes, in order (`signed_in{cause:…} — note` → `signed_in`). */
    private fun emitNames(row: JSONObject): List<String> =
        row.getJSONArray("emits").strings().map { e -> e.substringBefore("{").substringBefore(" ").trim() }

    private fun Result<*>.code(): String? = (exceptionOrNull() as? SendoraCloudAuthError)?.code

    private val NO_HINT_FIELDS = setOf("prevAnonRefreshToken", "linkAnonymous", "onCredentialInUse")

    /** The verbs `withheld | <event>` must refuse, one driver per fixture event. */
    private val REJECTED_IN_WITHHELD_DRIVERS: Map<String, suspend (SendoraCloudAuth) -> Result<*>> = mapOf(
        "MINT" to { a -> a.signInAnonymously() },
        "SIGN_IN" to { a -> a.signIn("b@x.io", "pw") },
        "LINK" to { a -> a.link(Credential.Password("b@x.io", "pw")) },
        "CLAIM" to { a -> a.claimHeldGuest("g1") },
        "RESTORE" to { a -> a.restoreHeldGuest("g1") },
        "DISCARD" to { a -> a.discardHeldGuest("g1") },
        "DELETE" to { a -> a.deleteAccount() },
        "SESSION_VERB" to { a -> a.disableMfa().also { a.revokeSession("x"); a.enrollMfa(); runCatching { a.listMySessions() } } },
    )

    // ─── one scenario per fixture row ──────────────────────────────────────

    private val SCENARIOS: Map<String, (JSONObject) -> Unit> = mapOf(
        "hydrate.coherent_match" to {
            val store = RecordingStore()
            store.seedLegacySession(uA, tokA(), "rA", expiresAt = 2_000_000_000_000L)
            val rig = Rig(store = store)
            assertEquals(AuthStatus.ANONYMOUS, rig.auth.status())
            assertEquals(uA.id, rig.auth.currentUser?.id)
            assertEquals("arm the proactive cron", 1, rig.cron.arms)
            assertNotNull("write-forward of auth_session from the four legacy keys", store.secure[AuthKeys.SESSION])
            assertEquals("schema_version → 2", "2", store.plain[AuthKeys.SCHEMA_VERSION])
            assertEquals("rA", store.secure[AuthKeys.REFRESH])
            val replay = mutableListOf<AuthStateChange>()
            rig.auth.onAuthStateChanged { replay += it }
            assertEquals("initial{status,user} once per subscriber", "initial", replay.first().event)
            assertEquals(AuthStatus.ANONYMOUS, (replay.first() as AuthStateChange.Initial).status)
            assertEquals(1, replay.count { it.event == "initial" })
            // Downgrade readability: a 4.25.0 reads the four frozen keys unchanged.
            assertEquals(tokA(), store.secure[AuthKeys.ACCESS])
            assertEquals(2_000_000_000_000L, store.secure[AuthKeys.EXPIRES])
        },
        "hydrate.project_mismatch" to {
            val rig = withheldRig()
            assertEquals(AuthStatus.WITHHELD, rig.auth.status())
            assertEquals("NOTHING on disk", emptyList<StoreWrite>(), rig.store.writes)
            assertNull("no auth_session write-forward", rig.store.secure[AuthKeys.SESSION])
            assertNull("no schema bump", rig.store.plain[AuthKeys.SCHEMA_VERSION])
            assertEquals("no cron", 0, rig.cron.arms)
            assertEquals("onIdentityWithheld()", 1, rig.withheldHooks)
            assertEquals(WithheldInfo(PROJECT_A, PROJECT_B, uA.id, true), rig.auth.withheld())
            assertNull(rig.auth.currentUser)
            val replay = mutableListOf<AuthStateChange>()
            rig.auth.onAuthStateChanged { replay += it }
            assertEquals(listOf("initial"), replay.map { it.event })
            assertEquals(AuthStatus.WITHHELD, (replay.single() as AuthStateChange.Initial).status)
            assertNotNull((replay.single() as AuthStateChange.Initial).withheld)
            assertTrue("never a replayed session_withheld", rig.events.none { it.event == "session_withheld" })
        },
        "hydrate.gap_fill" to {
            val rig = limboRig()
            assertEquals(AuthStatus.UNKNOWN, rig.auth.status())
            assertEquals("stay unknown, keep the refresh token", "rA", rig.store.secure[AuthKeys.REFRESH])
            assertEquals("the ONE gap-fill cron is armed", 1, rig.cron.arms)
            assertEquals("no writes", emptyList<StoreWrite>(), rig.store.writes)
            val replay = mutableListOf<AuthStateChange>()
            rig.auth.onAuthStateChanged { replay += it }
            assertEquals(listOf("initial"), replay.map { it.event })
            assertEquals(AuthStatus.UNKNOWN, (replay.single() as AuthStateChange.Initial).status)
            // The unreadable-claim variant: user readable, claim KEY absent → unknown, not match.
            val store = RecordingStore()
            store.seedLegacySession(uA.copy(projectKnown = false, project = null), jwt(uA.id, "sid-A", projectPresent = false), "rA", 2_000_000_000_000L)
            val guarded = Rig(store = store, expectedProjectId = PROJECT_A)
            assertEquals("absent claim is UNKNOWN, never installed", AuthStatus.UNKNOWN, guarded.auth.status())
            assertEquals(emptyList<StoreWrite>(), store.writes)
            // The refresh result is re-judged BEFORE install: a mismatching claim withholds.
            runBlocking {
                guarded.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(uA.copy(project = PROJECT_B), jwt(uA.id, "sid-A", project = PROJECT_B), "rA'"))
                guarded.auth.getAccessToken(forceRefresh = true)
                assertEquals(AuthStatus.WITHHELD, guarded.auth.status())
            }
        },
        "hydrate.stale_blob" to {
            val store = RecordingStore()
            store.seedLegacySession(uA, tokA(), refresh = null, expiresAt = 2_000_000_000_000L)
            val rig = Rig(store = store)
            assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
            assertNull(store.secure[AuthKeys.USER]); assertNull(store.secure[AuthKeys.ACCESS])
            assertTrue("the refresh key is never written", store.writesTo(AuthKeys.REFRESH).isEmpty())
            assertNull(rig.auth.currentUser)
        },
        "unknown.queue" to {
            runBlocking {
                for (verb in listOf("MINT", "SIGN_IN", "LINK", "RESTORE")) {
                    val rig = limboRig(withHeldG1 = verb == "RESTORE")
                    val gate = Gate()
                    rig.transport.on("/auth-service/token/refresh") { req ->
                        if (req.body!!["refreshToken"] == "rA") { gate.await(); refreshEnvelope(uA, tokA(), "rA'") }
                        else refreshEnvelope(user("g1", true), jwt("g1", "sid-g1"), "rG1'")
                    }
                    rig.transport.enqueue("/auth-service/anonymous", sessionEnvelope(user("fresh", true), jwt("fresh", "s"), "rF"))
                    rig.transport.enqueue("/auth-service/login", sessionEnvelope(uB, tokB(), "rB"))
                    rig.transport.enqueue("/auth-service/me/link/email", mapOf("success" to true, "data" to mapOf("user" to userMap(uB), "alreadyLinked" to false)))
                    val job = async(Dispatchers.Default) {
                        when (verb) {
                            "MINT" -> rig.auth.signInAnonymously()
                            "SIGN_IN" -> rig.auth.signIn("b@x.io", "pw")
                            "LINK" -> rig.auth.link(Credential.Password("b@x.io", "pw"))
                            else -> rig.auth.restoreHeldGuest("g1")
                        }
                    }
                    withTimeout(5_000) { gate.opened.await() }
                    delay(50)
                    assertEquals("$verb: QUEUED — the only request so far is the gap-fill refresh", listOf("/auth-service/token/refresh"), rig.transport.requests.map { it.path }.distinct())
                    assertEquals(AuthStatus.UNKNOWN, rig.auth.status())
                    gate.release()
                    val result = withTimeout(5_000) { job.await() }
                    assertTrue("$verb succeeded once settled: $result", result.isSuccess)
                    // The verb's own request (RESTORE's is the HELD token on /token/refresh) comes after the gap-fill's.
                    val gapFill = rig.transport.requests.indexOfFirst { it.body?.get("refreshToken") == "rA" }
                    val own = rig.transport.requests.indexOfFirst { it.path != "/auth-service/token/refresh" || it.body?.get("refreshToken") == "rG1" }
                    assertTrue("$verb ran only after the status settled", verb == "MINT" || own > gapFill && gapFill >= 0)
                    if (verb == "MINT") assertEquals("the settled guest is returned, nothing minted", 0, rig.transport.count("/auth-service/anonymous"))
                }
            }
        },
        "mint.fresh" to {
            runBlocking {
                val rig = signedOutRig()
                val minted = user("fresh", true)
                rig.transport.enqueue("/auth-service/anonymous", sessionEnvelope(minted, jwt("fresh", "sid-f"), "rF"))
                val r = rig.auth.signInAnonymously()
                assertEquals("fresh", r.getOrThrow().id)
                val body = rig.transport.sent("/auth-service/anonymous").single().body!!
                val mintKey = body["mintKey"] as String
                assertTrue("mintKey 16–128 chars (B10)", mintKey.length in 16..128)
                assertTrue(body.keys.none { it in NO_HINT_FIELDS })
                assertEquals(listOf("signed_in"), rig.eventNames)
                assertEquals(AuthSignedInCause.MINT, (rig.events.single() as AuthStateChange.SignedIn).cause)
                assertEquals(AuthStatus.ANONYMOUS, rig.auth.status())
                assertEquals("dual-write: the four frozen keys + auth_session", AuthKeys.SLOT_KEYS.toSet(), rig.store.writes.filter { it.tier == "secure" && it.value != null }.map { it.key }.toSet())
                assertEquals("2", rig.store.plain[AuthKeys.SCHEMA_VERSION])
                assertNull("the mint key is dropped on MINT_OK", rig.store.plain[AuthKeys.MINT_KEY])
                assertEquals(1, rig.cron.arms)
            }
        },
        "mint.auto_restore" to {
            runBlocking {
                // newest eligible restored, VISIBLY, nothing minted
                val rig = signedOutRig()
                rig.store.seedHeld(0, heldSlotJson("old", "rOld", heldAt = 10))
                rig.store.seedHeld(1, heldSlotJson("new", "rNew", heldAt = 20))
                val r = Rig(store = rig.store)
                r.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(user("new", true), jwt("new", "sid-new"), "rNew'"))
                assertEquals("new", r.auth.ensureSession().getOrThrow().id)
                // The order is read off the FIXTURE row (it was corrected in packages/shared
                // to install-then-release, the same as `restore.held_guest`), never restated here.
                assertEquals(emitNames(it), r.eventNames)
                assertEquals(listOf("signed_in", "guest_released"), r.eventNames)
                assertEquals(AuthSignedInCause.RESTORE, (r.events[0] as AuthStateChange.SignedIn).cause)
                assertEquals(GuestReleasedReason.RESTORED, (r.events[1] as AuthStateChange.GuestReleased).reason)
                assertEquals(0, r.transport.count("/auth-service/anonymous"))
                assertNull(r.store.secure[AuthKeys.HELD_SLOT_KEYS[1]]); assertNotNull(r.store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
                assertEquals("rNew'", r.auth.getRefreshToken())
                // dead newest → released {dead} → next → none left → mint in the SAME call
                val s2 = RecordingStore(); s2.seedHeld(0, heldSlotJson("dead", "rDead", heldAt = 30))
                val r2 = Rig(store = s2)
                r2.transport.enqueue("/auth-service/token/refresh", deadRefresh("deleted"))
                r2.transport.enqueue("/auth-service/anonymous", sessionEnvelope(user("fresh", true), jwt("fresh", "s"), "rF"))
                assertEquals("ensureSession() must never resolve without a session because of a dead slot", "fresh", r2.auth.ensureSession().getOrThrow().id)
                assertEquals(listOf("guest_released", "signed_in"), r2.eventNames)
                assertEquals("deleted", (r2.events[0] as AuthStateChange.GuestReleased).endReason)
                assertEquals(AuthSignedInCause.MINT, (r2.events[1] as AuthStateChange.SignedIn).cause)
                // transient error → abort, state untouched
                val s3 = RecordingStore(); s3.seedHeld(0, heldSlotJson("g", "rG", heldAt = 30))
                val r3 = Rig(store = s3)
                r3.transport.enqueue("/auth-service/token/refresh", null)
                assertTrue(r3.auth.ensureSession().isFailure)
                assertEquals(AuthStatus.SIGNED_OUT, r3.auth.status()); assertNotNull(s3.secure[AuthKeys.HELD_SLOT_KEYS[0]])
                // autoRestoreHeldGuest=false → mint while T < K
                val s4 = RecordingStore(); s4.seedHeld(0, heldSlotJson("g", "rG", heldAt = 30))
                val r4 = Rig(store = s4, autoRestoreHeldGuest = false)
                r4.transport.enqueue("/auth-service/anonymous", sessionEnvelope(user("fresh", true), jwt("fresh", "s"), "rF"))
                assertEquals("fresh", r4.auth.ensureSession().getOrThrow().id)
                assertEquals(0, r4.transport.count("/auth-service/token/refresh"))
            }
        },
        "mint.cap_no_eligible" to {
            runBlocking {
                val store = RecordingStore()
                for (i in 0 until 5) store.seedHeld(i, heldSlotJson("g$i", "r$i", heldAt = i.toLong(), autoRestore = false))
                val rig = Rig(store = store)
                val mark = store.writes.size
                val r = rig.auth.ensureSession()
                assertTrue(r.exceptionOrNull() is SendoraCloudAuthError.HeldGuestLimit)
                assertEquals("nothing mutated", mark, store.writes.size)
                assertEquals("no network", 0, rig.transport.requests.size)
                assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
            }
        },
        "mint.force_new_at_cap" to {
            runBlocking {
                // T == K from ANONYMOUS (4 held + the current guest) and from SIGNED_OUT (5 held)
                val s1 = RecordingStore(); for (i in 0 until 4) s1.seedHeld(i, heldSlotJson("g$i", "r$i", heldAt = i.toLong()))
                val r1 = anonymousRig(store = s1)
                val mark = s1.writes.size
                assertTrue(r1.auth.signInAnonymously(forceNew = true).exceptionOrNull() is SendoraCloudAuthError.HeldGuestLimit)
                assertEquals(mark, s1.writes.size); assertEquals(0, r1.transport.requests.size)
                assertEquals(uA.id, r1.auth.currentUser?.id)
                val s2 = RecordingStore(); for (i in 0 until 5) s2.seedHeld(i, heldSlotJson("g$i", "r$i", heldAt = i.toLong()))
                val r2 = Rig(store = s2)
                assertTrue(r2.auth.signInAnonymously(forceNew = true).exceptionOrNull() is SendoraCloudAuthError.HeldGuestLimit)
                assertEquals(0, r2.transport.requests.size)
            }
        },
        "mint.noop_over_session" to {
            runBlocking {
                for (rig in listOf(anonymousRig(), identifiedRig())) {
                    val before = rig.auth.currentUser
                    assertEquals(before, rig.auth.signInAnonymously().getOrThrow())
                    assertEquals("no network", 0, rig.transport.requests.size)
                    assertEquals(emptyList<String>(), rig.eventNames)
                    assertEquals(0, rig.store.writes.size)
                }
            }
        },
        "mint.force_new_holds_guest" to {
            runBlocking {
                val rig = anonymousRig()
                rig.transport.enqueue("/auth-service/anonymous", sessionEnvelope(user("fresh", true), jwt("fresh", "s"), "rF"))
                assertEquals("fresh", rig.auth.signInAnonymously(forceNew = true).getOrThrow().id)
                assertEquals(listOf("guest_held", "signed_in"), rig.eventNames)
                assertEquals(uA.id, (rig.events[0] as AuthStateChange.GuestHeld).userId)
                assertEquals(1, (rig.events[0] as AuthStateChange.GuestHeld).count)
                val slot = rig.store.heldJson(0)!!
                assertEquals(uA.id, slot.getString("userId")); assertEquals("rA", slot.getString("refreshToken")); assertEquals(PROJECT_A, slot.getString("project"))
                assertTrue("the slot lands under a LITERAL secure key — every written key is declared", rig.store.writes.filter { it.tier == "secure" }.all { it.key in AuthKeys.SECURE_KEYS })
                val heldWrite = rig.store.writes.indexOfFirst { it.key == AuthKeys.HELD_SLOT_KEYS[0] }
                val currentWrite = rig.store.writes.indexOfFirst { it.key == AuthKeys.REFRESH }
                assertTrue("the slot is written FIRST", heldWrite in 0 until currentWrite)
                assertEquals("B15 report is fire-and-forget after the hold", "rA", rig.transport.sent("/auth-service/guest/held").single().body!!["refreshToken"])
            }
        },
        "withheld.reject" to {
            runBlocking {
                for ((event, drive) in REJECTED_IN_WITHHELD_DRIVERS) {
                    val rig = withheldRig()
                    val r = drive(rig.auth)
                    val err = r.exceptionOrNull() as? SendoraCloudAuthError ?: throw AssertionError("$event did not fail")
                    assertEquals("$event rejects SESSION_WITHHELD", "SESSION_WITHHELD", err.code)
                    assertEquals(SendoraCloudAuthErrorKind.CONFIG, err.kind); assertFalse(err.retryable)
                    assertEquals("$event: NO network", 0, rig.transport.requests.size)
                    assertEquals("$event: NO write", emptyList<StoreWrite>(), rig.store.writes)
                    assertEquals(AuthStatus.WITHHELD, rig.auth.status())
                }
                val rig = withheldRig()
                assertNull("getAccessToken null in withheld", rig.auth.getAccessToken())
                assertNull(rig.auth.accessToken); assertNull(rig.auth.getRefreshToken())
                assertEquals("no refresh in withheld", 0, rig.transport.requests.size)
            }
        },
        "withheld.recompute" to {
            val rig = withheldRig()
            assertEquals(AuthStatus.WITHHELD, rig.auth.status())
            // Re-init with the matching key over the SAME untouched bytes → the coherent-match row.
            val again = Rig(store = rig.store, expectedProjectId = PROJECT_B)
            assertEquals("nothing was persisted, so nothing needs migrating", AuthStatus.ANONYMOUS, again.auth.status())
            assertEquals(uA.id, again.auth.currentUser?.id)
            // And with no key at all (rollback / guard off).
            assertEquals(AuthStatus.ANONYMOUS, Rig(store = withheldRig().store).auth.status())
        },
        "withheld.discard" to {
            runBlocking {
                for (viaSignOut in listOf(false, true)) {
                    val rig = withheldRig()
                    val before = rig.store.snapshot()
                    if (viaSignOut) rig.auth.signOut() else assertEquals(true, rig.auth.discardWithheld().getOrThrow())
                    assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
                    assertEquals("clears EXACTLY the slot's keys", AuthKeys.SLOT_KEYS.toSet(), rig.store.writes.map { it.key }.toSet())
                    assertTrue(rig.store.writes.all { it.value == null || it.value == 0L })
                    assertEquals("held slots KEPT", before["secure:" + AuthKeys.HELD_SLOT_KEYS[0]], rig.store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
                    assertEquals("fire-and-forget /token/revoke, LOCAL ONLY otherwise", listOf("/auth-service/token/revoke"), rig.transport.requests.map { it.path })
                    assertEquals("rA", rig.transport.requests.single().body!!["refreshToken"])
                    assertEquals(listOf("signed_out"), rig.eventNames)
                    assertEquals(AuthSignedOutReason.USER, (rig.events.single() as AuthStateChange.SignedOut).reason)
                    assertEquals("keeps user_id + queue (no parent wipe)", emptyList<AuthWipeEffects>(), rig.wipes)
                }
            }
        },
        "link.upgrade_from_anonymous" to {
            runBlocking {
                // typed link(): user_updated{link}, same sub, rotated pair installed
                val rig = anonymousRig()
                val promoted = uA.copy(isAnonymous = false, email = "a@x.io")
                rig.transport.enqueue("/auth-service/me/link/email", sessionEnvelope(promoted, jwt(uA.id, "sid-A", anonymous = false), "rA2", extra = mapOf("upgraded" to true, "alreadyLinked" to false, "linked" to mapOf("method" to "password"))))
                val r = rig.auth.link(Credential.Password("a@x.io", "pw")).getOrThrow() as LinkResult.Done
                assertTrue(r.upgraded); assertFalse(r.alreadyLinked)
                val req = rig.transport.sent("/auth-service/me/link/email").single()
                assertEquals("Bearer ${tokA()}", req.headers!!["Authorization"])
                assertTrue("INV-3: no guest hint", req.body!!.keys.none { it in NO_HINT_FIELDS })
                assertEquals(listOf("user_updated"), rig.eventNames)
                assertEquals(AuthStatus.IDENTIFIED, rig.auth.status()); assertEquals(uA.id, rig.auth.currentUser?.id)
                assertEquals("rA2", rig.auth.getRefreshToken())
                // legacy signature (signUp): ONE signed_in{link}, never both
                val rig2 = anonymousRig()
                rig2.transport.enqueue("/auth-service/me/link/email", sessionEnvelope(promoted, jwt(uA.id, "sid-A", anonymous = false), "rA2", extra = mapOf("upgraded" to true, "alreadyLinked" to false)))
                assertEquals(uA.id, rig2.auth.signUp("a@x.io", "pw").getOrThrow().id)
                assertEquals(listOf("signed_in"), rig2.eventNames)
                assertEquals(AuthSignedInCause.LINK, (rig2.events.single() as AuthStateChange.SignedIn).cause)
                assertEquals(0, rig2.transport.count("/auth-service/upgrade"))
                // 409 → typed credential_in_use, nothing mutated
                val rig3 = anonymousRig()
                rig3.transport.enqueue("/auth-service/me/link/email", errorEnvelope("CREDENTIAL_IN_USE", 409, details = mapOf("provider" to "password", "collision" to "email")))
                val cu = rig3.auth.link(Credential.Password("a@x.io", "pw")).getOrThrow() as LinkResult.CredentialInUse
                assertEquals("password", cu.provider); assertEquals(LinkCollision.EMAIL, cu.collision)
                assertEquals(0, rig3.store.writes.size); assertEquals(AuthStatus.ANONYMOUS, rig3.auth.status()); assertEquals(emptyList<String>(), rig3.eventNames)
            }
        },
        "link.over_identified" to {
            runBlocking {
                // alreadyLinked → no event, no write, no revoke
                val rig = identifiedRig()
                rig.transport.enqueue("/auth-service/me/link/play-games", okEnvelope(mapOf("user" to userMap(uB), "alreadyLinked" to true, "linked" to mapOf("method" to "playgames"))))
                val done = rig.auth.link(Credential.PlayGames("code")).getOrThrow() as LinkResult.Done
                assertTrue(done.alreadyLinked); assertFalse(done.upgraded)
                assertEquals(emptyList<String>(), rig.eventNames); assertEquals(0, rig.store.writes.size)
                assertEquals(listOf("/auth-service/me/link/play-games"), rig.transport.requests.map { it.path })
                // attached → user_updated{link}, user installed, NO token rotation
                val rig2 = identifiedRig()
                rig2.transport.enqueue("/auth-service/me/link/social", okEnvelope(mapOf("user" to userMap(uB.copy(name = "B")), "alreadyLinked" to false)))
                val r2 = rig2.auth.link(Credential.Social("google", idToken = "id")).getOrThrow() as LinkResult.Done
                assertFalse(r2.alreadyLinked); assertFalse(r2.upgraded)
                assertEquals(listOf("user_updated"), rig2.eventNames)
                assertEquals("rB", rig2.auth.getRefreshToken()); assertEquals("B", rig2.auth.currentUser?.name)
                // 409 → typed, nothing mutated; 403 → typed recent_auth_required, nothing mutated; NEVER /login
                val rig3 = identifiedRig()
                rig3.transport.enqueue("/auth-service/me/link/play-games", errorEnvelope("CREDENTIAL_IN_USE", 409, details = mapOf("provider" to "playgames", "collision" to "identity")))
                assertTrue(rig3.auth.link(Credential.PlayGames("code")).getOrThrow() is LinkResult.CredentialInUse)
                rig3.transport.enqueue("/auth-service/me/link/play-games", errorEnvelope("RECENT_AUTH_REQUIRED", 403))
                assertTrue(rig3.auth.link(Credential.PlayGames("code")).getOrThrow() is LinkResult.RecentAuthRequired)
                assertEquals(0, rig3.store.writes.size); assertEquals(emptyList<String>(), rig3.eventNames)
                assertTrue("INV-14: link never reaches a sign-in route", rig3.transport.requests.none { it.path.startsWith("/auth-service/login") })
                // the legacy wrapper with link = true over identified → the same LINK route, throws the typed kinds
                rig3.transport.enqueue("/auth-service/me/link/play-games", errorEnvelope("RECENT_AUTH_REQUIRED", 403))
                val legacy = rig3.auth.signInWithPlayGames("code", link = true)
                assertEquals(SendoraCloudAuthErrorKind.RECENT_AUTH_REQUIRED, (legacy.exceptionOrNull() as SendoraCloudAuthError).kind)
                assertTrue(rig3.transport.requests.none { it.path.startsWith("/auth-service/login") })
            }
        },
        "link.signed_out_is_sign_in" to {
            runBlocking {
                val rig = signedOutRig()
                rig.transport.enqueue("/auth-service/login/social", sessionEnvelope(uB, tokB(), "rB"))
                assertEquals(uB.id, rig.auth.loginSocial("google", idToken = "id", link = true).getOrThrow().id)
                val req = rig.transport.requests.single()
                assertEquals("/auth-service/login/social", req.path)
                assertNull("no Bearer — nothing to attach to", req.headers)
                assertTrue(req.body!!.keys.none { it in NO_HINT_FIELDS })
                assertEquals(listOf("signed_in"), rig.eventNames)
                assertEquals(AuthSignedInCause.SIGN_IN, (rig.events.single() as AuthStateChange.SignedIn).cause)
            }
        },
        "sign_in.switch" to {
            runBlocking {
                // from a guest: HOLD (post-refresh tokens) then ONE signed_in, no signed_out
                val rig = anonymousRig()
                rig.transport.enqueue("/auth-service/login", sessionEnvelope(uB, tokB(), "rB"))
                val r = rig.auth.signInWith(Credential.Password("b@x.io", "pw")).getOrThrow() as SignInResult.Done
                assertEquals(PreviousSession(uA.id, true, held = true), r.previous)
                assertEquals(mapOf("email" to "b@x.io", "password" to "pw"), rig.transport.sent("/auth-service/login").single().body)
                assertEquals(listOf("guest_held", "signed_in"), rig.eventNames)
                assertEquals(AuthSignedInCause.SIGN_IN, (rig.events[1] as AuthStateChange.SignedIn).cause)
                assertEquals("rA", rig.store.heldJson(0)!!.getString("refreshToken"))
                assertEquals(AuthStatus.IDENTIFIED, rig.auth.status())
                // identified → different identified: revoke of the previous refresh, nothing held
                val rig2 = identifiedRig()
                rig2.transport.enqueue("/auth-service/login", sessionEnvelope(uC, jwt(uC.id, "sid-C", anonymous = false), "rC"))
                val r2 = rig2.auth.signInWith(Credential.Password("c@x.io", "pw")).getOrThrow() as SignInResult.Done
                assertEquals(PreviousSession(uB.id, false, held = false), r2.previous)
                assertEquals("rB", rig2.transport.sent("/auth-service/token/revoke").single().body!!["refreshToken"])
                assertEquals(listOf("signed_in"), rig2.eventNames)
                assertEquals(0, rig2.auth.heldGuests().size)
                // mfaRequired → state unchanged
                val rig3 = anonymousRig()
                rig3.transport.enqueue("/auth-service/login", okEnvelope(mapOf("mfaRequired" to true, "mfaChallengeToken" to "ch", "user" to mapOf("id" to uB.id))))
                val mfa = rig3.auth.signInWith(Credential.Password("b@x.io", "pw")).getOrThrow() as SignInResult.MfaRequired
                assertEquals("ch", mfa.challengeToken); assertEquals(AuthStatus.ANONYMOUS, rig3.auth.status()); assertEquals(0, rig3.store.writes.size)
                rig3.transport.enqueue("/auth-service/mfa/challenge", sessionEnvelope(uB, tokB(), "rB"))
                assertTrue(mfa.verify("123456").getOrThrow() is SignInResult.Done)
                assertEquals(mapOf("challengeToken" to "ch", "code" to "123456"), rig3.transport.sent("/auth-service/mfa/challenge").single().body)
                // any failure → nothing changes
                val rig4 = anonymousRig()
                rig4.transport.enqueue("/auth-service/login", errorEnvelope("INVALID_CREDENTIALS", 401))
                assertTrue(rig4.auth.signIn("b@x.io", "bad").isFailure)
                assertEquals(0, rig4.store.writes.size); assertEquals(AuthStatus.ANONYMOUS, rig4.auth.status()); assertEquals(emptyList<String>(), rig4.eventNames)
                // interleaving: a refresh in flight during the sign-in → the HOLD records the POST-refresh token
                interleavingProbe()
            }
        },
        "sign_in.cas_mismatch" to {
            runBlocking {
                val rig = anonymousRig()
                val gate = Gate()
                rig.transport.on("/auth-service/login") { gate.await(); sessionEnvelope(uB, tokB(), "rB") }
                rig.transport.enqueue("/auth-service/token/refresh", deadRefresh("revoked"))
                val signIn = async(Dispatchers.Default) { rig.auth.signIn("b@x.io", "pw") }
                withTimeout(5_000) { gate.opened.await() }
                // the guest's refresh dies in the background while /login is in flight
                rig.auth.getAccessToken(forceRefresh = true)
                assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
                gate.release()
                val r = withTimeout(5_000) { signIn.await() }
                assertTrue("the result is DROPPED", r.exceptionOrNull() is SendoraCloudAuthError.Superseded)
                assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
                assertEquals("server session B is revoked, not left live", "rB", rig.transport.sent("/auth-service/token/revoke").single().body!!["refreshToken"])
                assertEquals(listOf("signed_out"), rig.eventNames)
            }
        },
        "refresh_ok.current_match" to {
            runBlocking {
                val rig = anonymousRig()
                rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(uA, tokA(), "rA'"))
                assertEquals(tokA(), rig.auth.getAccessToken(forceRefresh = true))
                assertEquals("rA'", rig.store.secure[AuthKeys.REFRESH]); assertEquals("rA'", rig.auth.getRefreshToken())
                assertEquals("a rotation is not a transition", emptyList<String>(), rig.eventNames)
                // gap-fill from UNKNOWN: recovering an identity the SDK had none of is
                // the 4.12.0 SignedIn with NO cause (RN `recover` parity, 1.29.0) — not
                // user_updated, which is reserved for a user object that changed
                // under a session that already had one.
                val limbo = limboRig()
                limbo.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(uA, tokA(), "rA'"))
                limbo.auth.getAccessToken()
                assertEquals(AuthStatus.ANONYMOUS, limbo.auth.status())
                assertEquals(listOf("signed_in"), limbo.eventNames)
                assertNull((limbo.events.single() as AuthStateChange.SignedIn).cause)
                assertEquals(listOf(uA.id), limbo.identityChanges)
                // the user object changed under a live session → user_updated{refresh}
                val live = anonymousRig()
                live.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(uA.copy(email = "new@x.io"), tokA(), "rA'"))
                live.auth.getAccessToken(forceRefresh = true)
                assertEquals(listOf("user_updated"), live.eventNames)
                assertEquals(AuthUserUpdatedCause.REFRESH, (live.events.single() as AuthStateChange.UserUpdated).cause)
            }
        },
        "refresh_ok.current_mismatch_withhold" to {
            runBlocking {
                val rig = anonymousRig(expectedProjectId = PROJECT_A)
                rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(uA.copy(project = PROJECT_B), jwt(uA.id, "sid-A", project = PROJECT_B), "rA'"))
                assertNull(rig.auth.getAccessToken(forceRefresh = true))
                assertEquals(AuthStatus.WITHHELD, rig.auth.status())
                assertEquals("persist the rotated pair and NOTHING else", setOf(AuthKeys.ACCESS, AuthKeys.REFRESH, AuthKeys.EXPIRES, AuthKeys.SESSION), rig.store.writes.map { it.key }.toSet())
                assertEquals("rA'", rig.store.secure[AuthKeys.REFRESH])
                assertNull("in-memory user uninstalled", rig.auth.currentUser)
                assertEquals("stop the cron", 1, rig.cron.disarms)
                assertEquals(1, rig.withheldHooks)
                assertEquals(listOf("session_withheld"), rig.eventNames)
                val e = rig.events.single() as AuthStateChange.SessionWithheld
                assertEquals(PROJECT_A, e.expectedProjectId); assertEquals(PROJECT_B, e.actualProjectId); assertEquals(uA.id, e.userId)
                assertEquals("no user_id removal", emptyList<AuthWipeEffects>(), rig.wipes)
            }
        },
        "refresh_ok.held_slot" to {
            runBlocking {
                val rig = identifiedRig()
                rig.store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                val r = Rig(store = rig.store)
                r.transport.on("/auth-service/token/refresh") { req ->
                    assertEquals("the held token is the one presented", "rG1", req.body!!["refreshToken"])
                    // CAS PER SLOT: at this moment the slot still holds rG1
                    assertEquals("rG1", r.store.heldJson(0)!!.getString("refreshToken"))
                    refreshEnvelope(user("g1", true), jwt("g1", "sid-g1"), "rG1'")
                }
                r.transport.on("/auth-service/merge") { req ->
                    assertEquals("the rotation is PERSISTED into the slot BEFORE /merge", "rG1'", r.store.heldJson(0)!!.getString("refreshToken"))
                    assertEquals("rG1'", req.body!!["anonRefreshToken"]); assertEquals("rB", req.body!!["refreshToken"])
                    okEnvelope(mapOf("mergedUserId" to uB.id, "deletedAnonymousId" to "g1", "eventsReassigned" to 3, "tokens" to mapOf("accessToken" to tokB("sid-B2"), "refreshToken" to "rB2", "expiresIn" to 900)))
                }
                val claim = r.auth.claimHeldGuest("g1").getOrThrow()
                assertEquals(3, claim.stats.eventsReassigned)
                assertEquals("the proactive cron never refreshes a held guest", listOf("/auth-service/token/refresh", "/auth-service/merge"), r.transport.requests.map { it.path })
                // a rotation whose `sent` matches a held slot after its slot moved on → DROPPED
                assertNull(r.store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
            }
        },
        "refresh_ok.unrouted_drop" to {
            runBlocking {
                val rig = anonymousRig()
                val gate = Gate()
                rig.transport.on("/auth-service/token/refresh") { gate.await(); refreshEnvelope(uA, tokA(), "rA'") }
                val refresh = async(Dispatchers.Default) { rig.auth.getAccessToken(forceRefresh = true) }
                withTimeout(5_000) { gate.opened.await() }
                rig.auth.signOut()
                assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
                val mark = rig.store.writes.size
                gate.release()
                assertNull(withTimeout(5_000) { refresh.await() })
                assertEquals("a refresh that landed after signOut installs NOTHING (P16)", mark, rig.store.writes.size)
                assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status()); assertNull(rig.store.secure[AuthKeys.REFRESH])
            }
        },
        "refresh_dead.current" to {
            runBlocking {
                for ((endReason, expected) in listOf("revoked" to AuthSignedOutReason.REVOKED, "deleted" to AuthSignedOutReason.DELETED, "expired" to AuthSignedOutReason.SESSION_EXPIRED, null to AuthSignedOutReason.SESSION_EXPIRED)) {
                    val rig = anonymousRig()
                    rig.transport.enqueue("/auth-service/token/refresh", deadRefresh(endReason))
                    assertNull(rig.auth.getAccessToken(forceRefresh = true))
                    assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
                    assertEquals(listOf("signed_out"), rig.eventNames)
                    assertEquals("endReason=$endReason", expected, (rig.events.single() as AuthStateChange.SignedOut).reason)
                    assertEquals("stop the cron", 1, rig.cron.disarms)
                    assertFalse("no anon-id rotation", rig.wipes.single().rotateDeviceId)
                    assertNull(rig.store.secure[AuthKeys.REFRESH]); assertNull(rig.store.secure[AuthKeys.SESSION])
                }
                // from UNKNOWN: the gap-fill died → signed_out, never a mint
                val limbo = limboRig()
                limbo.transport.enqueue("/auth-service/token/refresh", deadRefresh("expired"))
                assertTrue(limbo.auth.ensureSession().isSuccess.not() || limbo.transport.count("/auth-service/anonymous") <= 1)
                assertEquals(listOf("signed_out"), limbo.eventNames.filter { it == "signed_out" })
            }
        },
        "refresh_dead.held_slot" to {
            runBlocking {
                for ((endReason, released) in listOf("deleted" to true, "revoked" to true, "expired" to true, "reuse" to false, null to false)) {
                    val store = RecordingStore(); store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                    val rig = Rig(store = store)
                    rig.transport.enqueue("/auth-service/token/refresh", deadRefresh(endReason))
                    val r = rig.auth.restoreHeldGuest("g1")
                    if (released) {
                        assertTrue("$endReason releases", r.exceptionOrNull() is SendoraCloudAuthError.HeldGuestGone)
                        assertEquals(listOf("guest_released"), rig.eventNames)
                        val e = rig.events.single() as AuthStateChange.GuestReleased
                        assertEquals(GuestReleasedReason.DEAD, e.reason); assertEquals(endReason, e.endReason); assertEquals("g1", e.userId)
                        assertNull(store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
                    } else {
                        val err = r.exceptionOrNull() as SendoraCloudAuthError
                        assertTrue("$endReason keeps the slot: retryable restore_failed", err is SendoraCloudAuthError.RestoreFailed && err.retryable)
                        assertEquals(emptyList<String>(), rig.eventNames)
                        assertNotNull(store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
                    }
                }
            }
        },
        "refresh_transient.backoff" to {
            runBlocking {
                for (response in listOf(null, errorEnvelope("RATE_LIMIT_EXCEEDED", 429), errorEnvelope("INTERNAL", 500), errorEnvelope("UNAUTHORIZED", 401))) {
                    val rig = anonymousRig()
                    rig.transport.enqueue("/auth-service/token/refresh", response)
                    assertNull(rig.auth.getAccessToken(forceRefresh = true))
                    assertEquals("NO identity change", AuthStatus.ANONYMOUS, rig.auth.status())
                    assertEquals("rA", rig.auth.getRefreshToken()); assertEquals(emptyList<String>(), rig.eventNames); assertEquals(0, rig.store.writes.size)
                }
            }
        },
        "sign_out.local_first" to {
            runBlocking {
                val rig = anonymousRig()
                rig.store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                val r = Rig(store = rig.store)
                r.transport.on("/auth-service/token/revoke") { null } // the revoke hangs/fails — the user is still out
                r.auth.signOut()
                assertEquals(AuthStatus.SIGNED_OUT, r.auth.status())
                assertEquals(listOf("signed_out"), r.eventNames); assertEquals(AuthSignedOutReason.USER, (r.events.single() as AuthStateChange.SignedOut).reason)
                assertEquals("rA", r.transport.sent("/auth-service/token/revoke").single().body!!["refreshToken"])
                assertEquals(AuthWipeEffects(rotateDeviceId = true, clearQueue = false, clearUserId = true), r.wipes.single())
                assertNotNull("KEEP held slots", r.store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
                assertTrue(r.store.writes.none { it.key.startsWith("auth_held_") })
            }
        },
        "delete.account" to {
            runBlocking {
                val rig = identifiedRig()
                rig.store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                val r = Rig(store = rig.store)
                r.transport.enqueue("/auth-service/me", okEnvelope(mapOf("status" to "purged", "graceDays" to 0)))
                val res = r.auth.deleteAccount().getOrThrow()
                assertEquals("purged", res.status); assertEquals("result carries heldGuests: n", 1, res.heldGuests)
                assertEquals(AuthStatus.SIGNED_OUT, r.auth.status())
                assertEquals(listOf("signed_out"), r.eventNames); assertEquals(AuthSignedOutReason.ACCOUNT_DELETED, (r.events.single() as AuthStateChange.SignedOut).reason)
                assertEquals(AuthWipeEffects(rotateDeviceId = true, clearQueue = true, clearUserId = true), r.wipes.single())
                assertFalse("stamp autoRestore:false", r.store.heldJson(0)!!.getBoolean("autoRestore"))
                assertEquals("never touches a held guest server-side by default", 0, r.transport.count("/auth-service/guest/discard"))
                // integrator test 9: the next boot mints fresh — no auto-restore after account_deleted
                val next = Rig(store = r.store)
                next.transport.enqueue("/auth-service/anonymous", sessionEnvelope(user("fresh", true), jwt("fresh", "s"), "rF"))
                assertEquals("fresh", next.auth.ensureSession().getOrThrow().id)
                assertEquals(0, next.transport.count("/auth-service/token/refresh"))
                assertEquals("still held, explicit restore only", 1, next.auth.heldGuests().size)
                // alsoDiscardHeldGuests: DISCARD per slot AFTER the 2xx; a failed slot stays held and is reported
                val s2 = RecordingStore(); s2.seedLegacySession(uB, tokB(), "rB", 2_000_000_000_000L)
                s2.seedHeld(0, heldSlotJson("ok", "rOk", heldAt = 1)); s2.seedHeld(1, heldSlotJson("bad", "rBad", heldAt = 2))
                val r2 = Rig(store = s2)
                r2.transport.enqueue("/auth-service/me", okEnvelope(mapOf("status" to "purged")))
                r2.transport.on("/auth-service/guest/discard") { req -> if (req.body!!["refreshToken"] == "rOk") okEnvelope(mapOf("status" to "purged")) else null }
                val res2 = r2.auth.deleteAccount(alsoDiscardHeldGuests = true).getOrThrow()
                assertEquals(listOf("bad"), res2.heldGuestDiscardFailures); assertEquals(1, res2.heldGuests)
                assertTrue(r2.transport.requests.indexOfFirst { it.path == "/auth-service/me" } < r2.transport.requests.indexOfFirst { it.path == "/auth-service/guest/discard" })
            }
        },
        "claim.held_guest" to {
            runBlocking {
                val rig = identifiedRig()
                rig.store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                val r = Rig(store = rig.store)
                r.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(user("g1", true), jwt("g1", "sid-g1"), "rG1'"))
                r.transport.enqueue("/auth-service/merge", okEnvelope(mapOf("mergedUserId" to uB.id, "deletedAnonymousId" to "g1", "tokens" to mapOf("accessToken" to tokB("sid-B"), "refreshToken" to "rB2", "expiresIn" to 900))))
                val claim = r.auth.claimHeldGuest().getOrThrow()
                assertEquals(uB.id, claim.user.id); assertEquals("g1", claim.stats.deletedAnonymousId)
                assertEquals(listOf("user_updated", "guest_released"), r.eventNames)
                assertEquals(AuthUserUpdatedCause.MERGE, (r.events[0] as AuthStateChange.UserUpdated).cause)
                assertEquals(GuestReleasedReason.CLAIMED, (r.events[1] as AuthStateChange.GuestReleased).reason)
                assertEquals("install the rotated target pair", "rB2", r.auth.getRefreshToken())
                assertNull(r.store.secure[AuthKeys.HELD_SLOT_KEYS[0]])
                // dead held → release {dead}, abort before /merge
                val s2 = RecordingStore(); s2.seedLegacySession(uB, tokB(), "rB", 2_000_000_000_000L); s2.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                val r2 = Rig(store = s2)
                r2.transport.enqueue("/auth-service/token/refresh", deadRefresh("deleted"))
                assertTrue(r2.auth.claimHeldGuest("g1").exceptionOrNull() is SendoraCloudAuthError.HeldGuestGone)
                assertEquals(0, r2.transport.count("/auth-service/merge")); assertEquals(listOf("guest_released"), r2.eventNames)
                // no-arg with two held → AMBIGUOUS_HELD_GUEST, nothing mutated
                val s3 = RecordingStore(); s3.seedLegacySession(uB, tokB(), "rB", 2_000_000_000_000L)
                s3.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10)); s3.seedHeld(1, heldSlotJson("g2", "rG2", heldAt = 20))
                val r3 = Rig(store = s3)
                val m3 = s3.writes.size // the boot write-forward of the legacy seed is not the verb's
                val amb = r3.auth.claimHeldGuest().exceptionOrNull() as SendoraCloudAuthError
                assertEquals("AMBIGUOUS_HELD_GUEST", amb.code); assertEquals(0, r3.transport.requests.size); assertEquals("no-arg destructive verb with 2 held mutates nothing", m3, s3.writes.size)
            }
        },
        "restore.held_guest" to {
            runBlocking {
                // from SIGNED_OUT: signed_in{restore} then guest_released{restored}; current installed BEFORE the slot is removed
                val store = RecordingStore(); store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                val rig = Rig(store = store)
                rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(user("g1", true), jwt("g1", "sid-g1"), "rG1'"))
                assertEquals("g1", rig.auth.restoreHeldGuest().getOrThrow().id)
                assertEquals(emitNames(it), rig.eventNames)
                assertEquals(listOf("signed_in", "guest_released"), rig.eventNames)
                assertEquals(AuthSignedInCause.RESTORE, (rig.events[0] as AuthStateChange.SignedIn).cause)
                val installIdx = store.writes.indexOfFirst { it.key == AuthKeys.REFRESH && it.value == "rG1'" }
                val removeIdx = store.writes.indexOfLast { it.key == AuthKeys.HELD_SLOT_KEYS[0] && it.value == null }
                assertTrue("install the held record as current BEFORE removing the slot", installIdx in 0 until removeIdx)
                assertEquals(AuthStatus.ANONYMOUS, rig.auth.status())
                // from IDENTIFIED: the identified session is revoked fire-and-forget
                val s2 = RecordingStore(); s2.seedLegacySession(uB, tokB(), "rB", 2_000_000_000_000L); s2.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                val r2 = Rig(store = s2)
                r2.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(user("g1", true), jwt("g1", "sid-g1"), "rG1'"))
                assertEquals("g1", r2.auth.restoreHeldGuest("g1").getOrThrow().id)
                assertEquals("rB", r2.transport.sent("/auth-service/token/revoke").single().body!!["refreshToken"])
                assertEquals(0, r2.auth.heldGuests().size)
                // project check FIRST (client-side) → HeldGuestProjectMismatch, no network, slot kept
                val s3 = RecordingStore(); s3.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10, project = PROJECT_B))
                val r3 = Rig(store = s3, projectId = PROJECT_A)
                assertTrue(r3.auth.restoreHeldGuest("g1").exceptionOrNull() is SendoraCloudAuthError.HeldGuestProjectMismatch)
                assertEquals(0, r3.transport.requests.size); assertNotNull(s3.secure[AuthKeys.HELD_SLOT_KEYS[0]])
            }
        },
        "restore.over_anonymous_holds_current" to {
            runBlocking {
                val rig = anonymousRig()
                rig.store.seedHeld(1, heldSlotJson("g1", "rG1", heldAt = 10))
                val r = Rig(store = rig.store)
                r.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(user("g1", true), jwt("g1", "sid-g1"), "rG1'"))
                assertEquals("g1", r.auth.restoreHeldGuest("g1").getOrThrow().id)
                assertEquals(listOf("guest_held", "signed_in", "guest_released"), r.eventNames)
                val holdIdx = r.store.writes.indexOfFirst { it.key == AuthKeys.HELD_SLOT_KEYS[0] && it.value != null }
                val installIdx = r.store.writes.indexOfFirst { it.key == AuthKeys.REFRESH && it.value == "rG1'" }
                val releaseIdx = r.store.writes.indexOfLast { it.key == AuthKeys.HELD_SLOT_KEYS[1] && it.value == null }
                assertTrue("HOLD the current guest FIRST, then install, then release — T unchanged", holdIdx in 0 until installIdx && installIdx < releaseIdx)
                assertEquals(uA.id, r.store.heldJson(0)!!.getString("userId"))
                assertEquals(1, r.auth.heldGuests().size)
            }
        },
        "discard.held_guest" to {
            runBlocking {
                for ((response, released) in listOf(okEnvelope(mapOf("userId" to "g1", "status" to "purged")) to true, errorEnvelope("NOT_FOUND", 404) to true, errorEnvelope("INTERNAL", 500) to false, null to false)) {
                    val store = RecordingStore(); store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                    val rig = Rig(store = store)
                    rig.transport.enqueue("/auth-service/guest/discard", response)
                    val r = rig.auth.discardHeldGuest()
                    assertEquals("rG1", rig.transport.sent("/auth-service/guest/discard").single().body!!["refreshToken"])
                    assertEquals(released, r.isSuccess)
                    assertEquals("released=$released", released, store.secure[AuthKeys.HELD_SLOT_KEYS[0]] == null)
                    assertEquals(if (released) listOf("guest_released") else emptyList(), rig.eventNames)
                }
                val s2 = RecordingStore(); s2.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10)); s2.seedHeld(1, heldSlotJson("g2", "rG2", heldAt = 20))
                val r2 = Rig(store = s2)
                assertEquals("AMBIGUOUS_HELD_GUEST", r2.auth.discardHeldGuest().code()); assertEquals(0, r2.transport.requests.size)
            }
        },
        "reset.keeps_held" to {
            runBlocking {
                val s = RecordingStore(); s.seedLegacySession(uB, tokB(), "rB", 2_000_000_000_000L)
                s.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10)); s.seedHeld(1, heldSlotJson("g2", "rG2", heldAt = 20))
                val rig = Rig(store = s)
                rig.auth.resetSession(includeHeldGuests = false)
                assertEquals(AuthStatus.SIGNED_OUT, rig.auth.status())
                assertEquals(2, rig.auth.heldGuests().size)
                assertEquals(AuthWipeEffects(rotateDeviceId = true, clearQueue = true, clearUserId = true), rig.wipes.single())
                assertEquals(listOf("signed_out"), rig.eventNames)
                rig.auth.resetSession(includeHeldGuests = true)
                assertEquals(0, rig.auth.heldGuests().size)
                assertEquals(listOf("guest_released", "guest_released"), rig.eventNames.drop(1))
                assertTrue(rig.events.drop(1).all { (it as AuthStateChange.GuestReleased).reason == GuestReleasedReason.RESET })
                assertEquals("NO server delete", 0, rig.transport.count("/auth-service/guest/discard"))
                // in withheld: RESET = DISCARD_WITHHELD + queue clear
                val w = withheldRig()
                w.auth.resetSession(includeHeldGuests = false)
                assertEquals(AuthStatus.SIGNED_OUT, w.auth.status()); assertTrue(w.wipes.single().clearQueue); assertEquals(1, w.auth.heldGuests().size)
            }
        },
        "discard_withheld.precondition_false" to {
            runBlocking {
                for (rig in listOf(anonymousRig(), identifiedRig(), signedOutRig(), limboRig())) {
                    val before = rig.store.snapshot()
                    assertEquals(false, rig.auth.discardWithheld().getOrThrow())
                    assertEquals(before, rig.store.snapshot()); assertEquals(0, rig.transport.requests.size)
                }
            }
        },
        "claim.identified_only" to {
            runBlocking {
                for (rig in listOf(anonymousRig(), signedOutRig())) {
                    rig.store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 10))
                    val r = Rig(store = rig.store)
                    val mark = r.store.writes.size
                    assertTrue(r.auth.claimHeldGuest("g1").isFailure)
                    assertEquals("never reaches /merge", 0, r.transport.requests.size); assertEquals("nothing mutated", mark, r.store.writes.size)
                }
            }
        },
        "session_verb.pass_through" to {
            runBlocking {
                val rig = anonymousRig()
                rig.transport.enqueue("/auth-service/mfa/disable", errorEnvelope("RECENT_AUTH_REQUIRED", 403))
                val r = rig.auth.disableMfa()
                assertEquals("a refusal surfaces through the Outcome", SendoraCloudAuthErrorKind.RECENT_AUTH_REQUIRED, (r.exceptionOrNull() as SendoraCloudAuthError).kind)
                // Built from the id, exactly as revokeSession() builds it, so the
                // ADR-023 golden's route auto-discovery sees `/sessions/me/<param>`
                // and not a fake literal path.
                val sessionId = "2f9c1d4e-0000-4000-8000-000000000009"
                rig.transport.enqueue("/auth-service/sessions/me/$sessionId", errorEnvelope("NOT_FOUND", 404))
                assertTrue(rig.auth.revokeSession(sessionId).isFailure)
                assertEquals("not a transition", emptyList<String>(), rig.eventNames); assertEquals(AuthStatus.ANONYMOUS, rig.auth.status())
                assertEquals("Bearer ${tokA()}", rig.transport.requests.first().headers!!["Authorization"])
            }
        },
    )

    /**
     * §3.3 interleaving: a refresh of the guest is in flight when the sign-in
     * starts. The attempt awaits it at START (the `/login` POST is sent only
     * after the rotation landed) and the HOLD records the POST-refresh token.
     */
    private suspend fun interleavingProbe() {
        val rig = anonymousRig()
        val gate = Gate()
        rig.transport.on("/auth-service/token/refresh") { gate.await(); refreshEnvelope(uA, tokA(), "rA'") }
        rig.transport.enqueue("/auth-service/login", sessionEnvelope(uB, tokB(), "rB"))
        val refresh = kotlinx.coroutines.CoroutineScope(Dispatchers.Default).async { rig.auth.getAccessToken(forceRefresh = true) }
        withTimeout(5_000) { gate.opened.await() }
        val signIn = kotlinx.coroutines.CoroutineScope(Dispatchers.Default).async { rig.auth.signIn("b@x.io", "pw") }
        delay(100)
        assertEquals("the sign-in awaits the in-flight refresh at START", 0, rig.transport.count("/auth-service/login"))
        gate.release()
        withTimeout(5_000) { refresh.await(); signIn.await().getOrThrow() }
        val held = rig.store.heldJson(0)!!
        assertEquals("the HOLD carries the post-refresh token", "rA'", held.getString("refreshToken"))
        assertEquals("rA'", held.getString("tokenAtHold"))
        val paths = rig.transport.requests.map { it.path }
        assertTrue(paths.indexOf("/auth-service/token/refresh") < paths.indexOf("/auth-service/login"))
    }
}
