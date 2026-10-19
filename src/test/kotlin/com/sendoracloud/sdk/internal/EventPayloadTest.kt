package com.sendoracloud.sdk.internal

import com.sendoracloud.sdk.buildEventPayload
import com.sendoracloud.sdk.isValidScreenName
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import com.sendoracloud.sdk.SendoraCloud
import kotlinx.coroutines.runBlocking

/**
 * 4.28.0 — the event payload never carries a null value. Asserted on the MAP,
 * not on serialized JSON: Android's built-in org.json writes a null value as JSON
 * `null` (which `projectId: z.string().uuid().optional()` rejects), while the
 * JVM's org.json 20231013 on this classpath omits it — so a JSON-level test
 * would pass here and fail on every device.
 */
class EventPayloadTest {

    private fun nullPaths(v: Any?, path: String = "$"): List<String> = when (v) {
        null, org.json.JSONObject.NULL -> listOf(path)
        is Map<*, *> -> v.flatMap { (k, x) -> nullPaths(x, "$path.$k") }
        is List<*> -> v.flatMapIndexed { i, x -> nullPaths(x, "$path[$i]") }
        else -> emptyList()
    }

    @Test
    fun `an app initialised without a projectId sends no null projectId`() {
        val event = buildEventPayload(
            projectId = null, name = "level_won", timestamp = "2026-10-18T00:00:00.000Z",
            properties = null, device = null, sessionId = null, userId = null, anonymousId = null, identityToken = null,
        )
        assertEquals("no null anywhere", emptyList<String>(), nullPaths(event))
        assertFalse(event.containsKey("projectId"))
        assertFalse(event.containsKey("anonymousId"))
        assertFalse(event.containsKey("identityToken"))
    }

    @Test
    fun `every value that is known is written`() {
        val event = buildEventPayload(
            projectId = "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b", name = "e", timestamp = "t",
            properties = mapOf("k" to 1), device = mapOf("os" to "Android"), sessionId = "s",
            userId = null, anonymousId = "anon", identityToken = "it",
        )
        assertEquals("6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b", event["projectId"])
        assertEquals("anon", event["anonymousId"])
        assertEquals("it", event["identityToken"])
        assertEquals(emptyList<String>(), nullPaths(event))
    }

    @Test
    fun `screen names share the 128-character event-name bound`() {
        assertTrue(isValidScreenName("a".repeat(128)))
        assertFalse(isValidScreenName("a".repeat(129)))
        assertFalse(isValidScreenName(""))
    }

    @Test
    fun `a lone queued event still goes to the batch route`() = runBlocking {
        TestHttpResponder().use { http ->
            http.answer(201, """{"success":true,"data":{"accepted":1}}""")
            val r = SendoraCloud.flushEvents(listOf(mapOf("module" to "custom", "eventType" to "e")), ApiClient(http.baseUrl, "pk_test"))
            assertEquals(listOf("/api/v1/events/batch"), http.paths.toList())
            assertEquals(201, (r as FlushResult.Sent).status)
        }
    }
}
