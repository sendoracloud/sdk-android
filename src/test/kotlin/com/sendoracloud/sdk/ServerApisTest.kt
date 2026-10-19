package com.sendoracloud.sdk

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * 4.29.0 — server consent + flags: the identity-token rule (port of RN
 * `withInputIdentityToken`), the no-null bodies, decoding and typed errors.
 *
 * The token-rule tests drive the REAL `SendoraCloud.identify()` / `reset()`
 * wiring (the singleton's `isConfigured` flipped by reflection — `init()` needs
 * a Context; identify / reset touch nothing else that does).
 */
class ServerApisTest {

    private val tok = "hmac_v1:" + "a".repeat(64)

    private fun setConfigured(v: Boolean) {
        SendoraCloud::class.java.getDeclaredField("isConfigured").apply { isAccessible = true }.setBoolean(SendoraCloud, v)
    }

    @Before fun configure() = setConfigured(true)

    @After fun unconfigure() {
        SendoraCloud.reset()
        setConfigured(false)
    }

    private fun nullPaths(m: Map<String, Any?>): List<String> = m.filterValues { it == null }.keys.toList()

    // ─── the rule ────────────────────────────────────────────────────────────

    @Test
    fun `identify's token rides along for the identified user only`() {
        SendoraCloud.identify("u1", options = SendoraCloudIdentifyOptions(identityToken = tok))
        val flags = SendoraCloud.flags.evaluateBody("f", null, null, null, null)
        assertEquals("userId defaults to the identified user", "u1", flags["userId"])
        assertEquals(tok, flags["identityToken"])
        assertEquals(tok, SendoraCloud.consent.recordBody("analytics", true, null, "u1", null, null, null)["identityToken"])
        assertEquals(tok, SendoraCloud.consent.deletionBody(null, "u1", null, null, null)["identityToken"])
        assertEquals(tok, SendoraCloud.flags.evaluateAllBody(null, null, null, null)["identityToken"])
    }

    @Test
    fun `never for another userId, nor for a consent call that names no user`() {
        SendoraCloud.identify("u1", options = SendoraCloudIdentifyOptions(identityToken = tok))
        assertFalse(SendoraCloud.flags.evaluateBody("f", "u2", null, null, null).containsKey("identityToken"))
        assertFalse(SendoraCloud.flags.evaluateAllBody("u2", null, null, null).containsKey("identityToken"))
        assertFalse(SendoraCloud.consent.recordBody("analytics", true, null, "u2", null, null, null).containsKey("identityToken"))
        assertFalse(SendoraCloud.consent.deletionBody(null, "u2", null, null, null).containsKey("identityToken"))
        // RN parity: consent's userId does NOT default to the identified user, so no token either.
        val anon = SendoraCloud.consent.recordBody("analytics", true, null, null, "a@b.co", null, null)
        assertFalse(anon.containsKey("identityToken")); assertFalse(anon.containsKey("userId"))
    }

    @Test
    fun `an explicit token wins, for any user`() {
        SendoraCloud.identify("u1", options = SendoraCloudIdentifyOptions(identityToken = tok))
        assertEquals("mine", SendoraCloud.flags.evaluateBody("f", "u2", null, null, "mine")["identityToken"])
        assertEquals("mine", SendoraCloud.consent.recordBody("analytics", true, null, "u1", null, null, "mine")["identityToken"])
    }

    @Test
    fun `a remembered token over the route's limit is not sent`() {
        val t200 = "t".repeat(200)
        SendoraCloud.identify("u1", options = SendoraCloudIdentifyOptions(identityToken = t200))
        assertFalse("flags take ≤ 128", SendoraCloud.flags.evaluateBody("f", null, null, null, null).containsKey("identityToken"))
        assertEquals("consent takes ≤ 256", t200, SendoraCloud.consent.recordBody("analytics", true, null, "u1", null, null, null)["identityToken"])
        SendoraCloud.identify("u1", options = SendoraCloudIdentifyOptions(identityToken = "t".repeat(257)))
        assertFalse(SendoraCloud.consent.deletionBody(null, "u1", null, null, null).containsKey("identityToken"))
    }

    @Test
    fun `after reset, or an identify without a token, nothing is sent`() {
        SendoraCloud.identify("u1", options = SendoraCloudIdentifyOptions(identityToken = tok))
        SendoraCloud.reset()
        assertNull(SendoraCloud.identityProof())
        assertFalse(SendoraCloud.consent.recordBody("analytics", true, null, "u1", null, null, null).containsKey("identityToken"))
        SendoraCloud.identify("u1", options = SendoraCloudIdentifyOptions(identityToken = tok))
        SendoraCloud.identify("u1") // a later identify without a token forgets the old one
        assertFalse(SendoraCloud.flags.evaluateBody("f", "u1", null, null, null).containsKey("identityToken"))
    }

    @Test
    fun `bodies never carry a null value`() {
        assertEquals(emptyList<String>(), nullPaths(SendoraCloud.consent.recordBody("marketing", false, null, null, null, null, null)))
        assertEquals(emptyList<String>(), nullPaths(SendoraCloud.consent.deletionBody(null, null, null, null, null)))
        assertEquals(emptyList<String>(), nullPaths(SendoraCloud.flags.evaluateBody("f", null, null, null, null)))
        assertEquals(emptyList<String>(), nullPaths(SendoraCloud.flags.evaluateAllBody(null, null, null, null)))
        assertEquals(setOf("purpose", "granted"), SendoraCloud.consent.recordBody("marketing", false, null, null, null, null, null).keys)
    }

    // ─── over a transport: decoding + typed errors ───────────────────────────

    @Test
    fun `responses decode to typed results`() = runBlocking {
        val t = StubTransport()
        t.enqueue("/feature-flags/evaluate", okEnvelope(mapOf("key" to "dark", "value" to true, "ruleMatched" to "default")))
        t.enqueue("/feature-flags/evaluate-all", mapOf("success" to true, "data" to listOf(
            mapOf("key" to "a", "value" to "blue", "ruleMatched" to "rule_1"), mapOf("key" to "b", "value" to null, "ruleMatched" to "inactive"))))
        t.enqueue("/consent/record", okEnvelope(mapOf("id" to "c1", "purpose" to "analytics", "granted" to true, "userId" to "u1", "sourceVerified" to true)))
        t.enqueue("/consent/deletion-request", okEnvelope(mapOf("id" to "d1", "status" to "pending", "userId" to "u1")))
        val flags = SendoraCloudFlags({ t }, { "u1" }, { null })
        assertEquals(FlagValue("dark", true, null, "default"), flags.evaluate("dark"))
        val all = flags.evaluateAll()
        assertEquals(setOf("a", "b"), all.keys)
        assertEquals("blue", all["a"]!!.value); assertEquals("rule_1", all["a"]!!.reason)
        val consent = SendoraCloudConsent(false, { t }, { null })
        val rec = consent.record("analytics", true, userId = "u1")
        assertEquals("c1", rec.id); assertTrue(rec.granted); assertEquals(true, rec.sourceVerified)
        assertEquals("pending", consent.requestDeletion(userId = "u1").status)
        assertFalse("the local gate is untouched", consent.isGranted)
    }

    @Test
    fun `a refusal is a thrown typed exception with status and code, never a null`() = runBlocking {
        val t = StubTransport()
        t.enqueue("/consent/record", errorEnvelope("VALIDATION_ERROR", 400, "bad purpose"))
        t.enqueue("/feature-flags/evaluate", null) // no answer
        val consent = SendoraCloudConsent(false, { t }, { null })
        try { consent.record("nope", true); fail("must throw") } catch (e: SendoraCloudApiException) {
            assertEquals(400, e.status); assertEquals("VALIDATION_ERROR", e.code); assertEquals("consent.record", e.operation)
        }
        try { SendoraCloudFlags({ t }, { null }, { null }).evaluate("x"); fail("must throw") } catch (e: SendoraCloudApiException) {
            assertEquals(0, e.status); assertEquals("NETWORK", e.code)
        }
        try { SendoraCloudFlags({ null }, { null }, { null }).evaluateAll(); fail("must throw") } catch (e: SendoraCloudApiException) {
            assertEquals("NOT_CONFIGURED", e.code)
        }
    }
}
