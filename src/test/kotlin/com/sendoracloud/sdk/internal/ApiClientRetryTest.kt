package com.sendoracloud.sdk.internal

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * 4.28.0 (F67) — the transport's reading of `Retry-After` / `cf-mitigated` and
 * the breaker built on it, against a real HTTP server on 127.0.0.1 (the real
 * `HttpURLConnection` path, headers and all — nothing mocked).
 */
class ApiClientRetryTest {

    private lateinit var http: TestHttpResponder
    private var now = 1_760_000_000_000L
    private val hits get() = http.hits

    @Before
    fun start() { http = TestHttpResponder() }

    @After
    fun stop() = http.close()

    private fun client(random: (Long) -> Long = { 0L }) =
        ApiClient(http.baseUrl, "pk_test", clock = { now }, random = random)

    private fun answer(code: Int, json: String?, vararg h: Pair<String, String>) = http.answer(code, json, *h)

    @Suppress("UNCHECKED_CAST")
    private fun details(env: Map<String, Any?>?) = ((env?.get("error") as? Map<String, Any?>)?.get("details") as? Map<String, Any?>)

    @Test
    fun `a 429 surfaces Retry-After and holds the client for it`() = runBlocking {
        val c = client()
        answer(429, """{"success":false,"error":{"code":"RATE_LIMITED","message":"slow"}}""", "Retry-After" to "30")
        val env = c.post("/events", mapOf("a" to 1))
        assertEquals("a header-only wait reaches the envelope", 30L, (details(env)?.get("retryAfterSeconds") as Number).toLong())
        assertEquals(429, ((env?.get("error") as Map<*, *>)["status"] as Number).toInt())
        assertEquals("held for the server's wait", 30_000L, c.breakerWaitMs())
        assertNull("…and a call inside it never leaves the device", c.post("/events", emptyMap()))
        assertEquals(1, hits)
    }

    @Test
    fun `a 429's whole-client hold is clamped to 60 s, the full wait is surfaced`() = runBlocking {
        val c = client()
        answer(429, """{"success":false,"error":{"code":"RATE_LIMITED","message":"m","details":{"retryAfterSeconds":600}}}""", "Retry-After" to "600")
        val rich = c.requestWithDetails("POST", "/support/tickets", emptyMap())
        assertEquals(600L, rich.retryAfterSeconds)
        assertEquals("a per-route budget must not black out events + refresh for 10 min", 60_000L, c.breakerWaitMs())
    }

    @Test
    fun `a 503 waits at least the server's Retry-After`() = runBlocking {
        val c = client()
        answer(503, """{"success":false,"error":{"code":"OVERLOADED","message":"m"}}""", "Retry-After" to "120")
        val rich = c.requestWithDetails("POST", "/events/batch", emptyMap())
        assertEquals(503, rich.statusCode)
        assertEquals(120L, rich.retryAfterSeconds)
        assertEquals(120_000L, c.breakerWaitMs())
        val skipped = c.requestWithDetails("POST", "/events/batch", emptyMap())
        assertEquals("refused locally, with the time left", 0, skipped.statusCode)
        assertEquals(120L, skipped.retryAfterSeconds)
    }

    @Test
    fun `an edge challenge is null on the envelope path - never a refusal an auth call could read as dead`() = runBlocking {
        val c = client()
        // Even a JSON body that LOOKS like the dead-session verdict: the backend never said it.
        answer(403, """{"success":false,"error":{"code":"INVALID_REFRESH_TOKEN","message":"m"}}""", "cf-mitigated" to "challenge")
        assertNull(c.post("/auth-service/token/refresh", mapOf("refreshToken" to "r")))
        assertTrue("an edge challenge waits at least 60 s", c.breakerWaitMs() >= 60_000L)
    }

    @Test
    fun `an edge challenge on the rich path is flagged, with the edge's status`() = runBlocking {
        val c = client()
        answer(503, "<html>challenge</html>", "cf-mitigated" to "challenge", "Retry-After" to "90")
        val rich = c.requestWithDetails("POST", "/sdk/links", emptyMap())
        assertTrue(rich.cfMitigated)
        assertEquals(503, rich.statusCode)
        assertEquals("CF_CHALLENGE", rich.errorCode)
        assertEquals(90_000L, c.breakerWaitMs())
    }

    @Test
    fun `a plain 4xx never trips the breaker`() = runBlocking {
        for (code in listOf(400, 401, 403, 404, 409, 413, 422)) {
            val c = client { it }
            answer(code, """{"success":false,"error":{"code":"X","message":"m"}}""", "Retry-After" to "60")
            val env = c.post("/auth-service/login", mapOf("email" to "a@b.c"))
            assertNotNull("$code is the backend answering", env)
            assertEquals("$code: no wait", 0L, c.breakerWaitMs())
        }
    }

    @Test
    fun `a bodiless refusal is an answer, not a transport failure`() = runBlocking {
        val c = client { it }
        answer(403, null)
        val rich = c.requestWithDetails("POST", "/support/csat", emptyMap())
        assertEquals(403, rich.statusCode)
        assertEquals("the null errorStream used to throw and arm the breaker", 0L, c.breakerWaitMs())
    }

    @Test
    fun `the breaker uses full jitter, not fixed doubling`() {
        val draws = mutableListOf<Long>()
        val c = ApiClient("https://example.invalid", "pk", clock = { now }, random = { b -> draws += b; b / 2 })
        c.recordAnswer(500, null, false)
        assertEquals(1_000L, c.breakerWaitMs())
        c.recordAnswer(502, null, false)
        assertEquals(2_000L, c.breakerWaitMs())
        assertEquals("random(0, 2^n s)", listOf(2_000L, 4_000L), draws)
        c.recordAnswer(200, null, false)
        assertEquals(0L, c.breakerWaitMs())
        assertFalse(draws.isEmpty())
    }

    @Test
    fun `a 2xx resets the breaker`() = runBlocking {
        val c = client { it }
        c.recordAnswer(500, null, false)
        now += 10_000L
        answer(200, """{"success":true}""")
        assertNotNull(c.post("/events", emptyMap()))
        assertEquals(0L, c.breakerWaitMs())
    }
}
