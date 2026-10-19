package com.sendoracloud.sdk

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * The body keys this SDK sends equal the backend's zod schema keys — read from
 * `packages/shared/src/types/auth-service.ts` (the schema the route validates
 * with), never restated here.
 *
 * Why: the first Android live run (4.28.0) found `POST /auth-service/merge` sent
 * `{ anonRefreshToken, refreshToken }` while `authMergeSchema` is
 * `{ anonymousRefreshToken, targetRefreshToken }` — a 400 on every claim. Every
 * unit suite passed, because each asserted the SDK's own (wrong) names: a test
 * that restates the wire contract only proves the SDK agrees with itself.
 */
class WireSchemaContractTest {

    /** The top-level keys of `export const <name> = z.object({ … })` in the shared types. */
    private fun schemaKeys(name: String, types: String = "auth-service"): Set<String> {
        val file = repoFile("packages/shared/src/types/$types.ts")
        assertNotNull("packages/shared/src/types/$types.ts is found from the module dir", file)
        val src = file!!.readText()
        val start = src.indexOf("export const $name = z.object({")
        check(start >= 0) { "$name not found" }
        var depth = 0
        var i = src.indexOf('{', start)
        val bodyStart = i + 1
        while (true) {
            when (src[i]) { '{' -> depth++; '}' -> { depth--; if (depth == 0) break } }
            i++
        }
        val body = src.substring(bodyStart, i)
        // Top-level `key:` entries only (nested objects are skipped by tracking depth).
        val keys = mutableSetOf<String>()
        var d = 0
        Regex("""([{}])|^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:""", RegexOption.MULTILINE).findAll(body).forEach { m ->
            when (m.groupValues[1]) {
                "{" -> d++
                "}" -> d--
                else -> if (d == 0) keys += m.groupValues[2]
            }
        }
        return keys
    }

    private val uB = user("bbbbbbbb-0000-4000-8000-000000000002", anonymous = false, email = "b@x.io")

    @Test
    fun `claimHeldGuest sends exactly authMergeSchema's keys`() = runBlocking {
        val expected = schemaKeys("authMergeSchema")
        assertEquals(setOf("anonymousRefreshToken", "targetRefreshToken"), expected) // sanity: the parser works
        val store = RecordingStore()
        store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 1))
        store.seedLegacySession(uB, jwt(uB.id, "sid-B", anonymous = false), "rB", 2_000_000_000_000L)
        val rig = Rig(store = store)
        rig.transport.enqueue("/auth-service/token/refresh", refreshEnvelope(user("g1", true), jwt("g1", "sid-g1"), "rG1b"))
        rig.transport.enqueue("/auth-service/merge", okEnvelope(mapOf("mergedUserId" to uB.id, "deletedAnonymousId" to "g1",
            "tokens" to mapOf("accessToken" to jwt(uB.id, "sid-B", anonymous = false), "refreshToken" to "rB2", "expiresIn" to 900))))
        rig.auth.claimHeldGuest("g1").getOrThrow()
        val body = rig.transport.sent("/auth-service/merge").single().body!!
        assertEquals("the /merge body keys ARE the schema's", expected, body.keys)
        assertEquals("rG1b", body["anonymousRefreshToken"])
        assertEquals("rB", body["targetRefreshToken"])
    }

    @Test
    fun `discardHeldGuest sends exactly authGuestDiscardSchema's keys`() = runBlocking {
        val expected = schemaKeys("authGuestDiscardSchema")
        val store = RecordingStore()
        store.seedHeld(0, heldSlotJson("g1", "rG1", heldAt = 1))
        store.seedLegacySession(uB, jwt(uB.id, "sid-B", anonymous = false), "rB", 2_000_000_000_000L)
        val rig = Rig(store = store)
        rig.transport.enqueue("/auth-service/guest/discard", okEnvelope(mapOf("userId" to "g1", "status" to "purged")))
        rig.auth.discardHeldGuest("g1").getOrThrow()
        assertEquals(expected, rig.transport.sent("/auth-service/guest/discard").single().body!!.keys)
    }

    // ─── 4.29.0: consent + flags ────────────────────────────────────────────

    private val consent = SendoraCloudConsent(false, { null }, { null })
    private val flags = SendoraCloudFlags({ null }, { null }, { null })
    private val entity = "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b"

    @Test
    fun `consent record sends recordConsentSchema's keys (all but the two Android does not offer)`() {
        val schema = schemaKeys("recordConsentSchema", "consent")
        val sent = consent.recordBody("analytics", true, entity, "u1", "a@b.co", "banner", "tok").keys
        assertEquals("every key sent is the schema's", emptySet<String>(), sent - schema)
        assertEquals("phone (SMS) and ipHash (secret keys only) are the only schema keys not offered", setOf("phone", "ipHash"), schema - sent)
    }

    @Test
    fun `consent deletion-request sends exactly createDeletionRequestSchema's keys`() {
        assertEquals(schemaKeys("createDeletionRequestSchema", "consent"), consent.deletionBody(entity, "u1", "a@b.co", "why", "tok").keys)
    }

    @Test
    fun `flags evaluate and evaluate-all send exactly their schemas' keys`() {
        assertEquals(schemaKeys("evaluateFlagSchema", "feature-flags"), flags.evaluateBody("k", "u1", entity, "production", "tok").keys)
        assertEquals(schemaKeys("evaluateAllFlagsSchema", "feature-flags"), flags.evaluateAllBody("u1", entity, "production", "tok").keys)
    }
}
