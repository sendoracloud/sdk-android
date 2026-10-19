package com.sendoracloud.sdk.internal

import com.sendoracloud.sdk.buildEventPayload
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * s58.405 — the persisted event queue keeps `userId` and never stores the identity token.
 *
 * ≤ 4.29.0 `Storage.saveEventQueue` stripped `userId` ("re-injected from currentUserId at send time" — nothing
 * did). An identified event carries `userId` INSTEAD of `anonymousId`, so after a relaunch it went out with
 * neither, and `decorateWithIdentity` (matches on `userId`) could never give it the send-time token. It also
 * wrote the enqueue-time `identityToken` (trackEvent stamps it) to plain SharedPreferences.
 * Driven through the real [Storage] over [MemoryPrefs] (one map = one device's `sendora_sdk.xml`).
 */
class PersistedQueueIdentityTest {

    private fun identified(name: String, userId: String, token: String? = null) = buildEventPayload(
        projectId = null, name = name, timestamp = "2026-10-19T00:00:00.000Z",
        properties = mapOf("level" to 3, "traits" to mapOf("plan" to "pro")), device = mapOf("os" to "Android"),
        sessionId = "s1", userId = userId, anonymousId = null, identityToken = token,
    )

    @Test
    fun `a queued event keeps its userId across a relaunch and no wire field is dropped`() = runBlocking {
        val disk = mutableMapOf<String, Any?>()
        val original = identified("level.complete", "user-42", token = "tok-at-enqueue")
        val q = EventQueue(Storage(MemoryPrefs(disk), null), flushAt = Int.MAX_VALUE)
        q.add(original)
        q.persistToDisk()

        val restored = EventQueue(Storage(MemoryPrefs(disk), null), flushAt = Int.MAX_VALUE).snapshot()
        assertEquals(1, restored.size)
        val e = restored[0]
        assertEquals("the persisted queue dropped the event's user", "user-42", e["userId"])
        assertFalse("an identified event has no anonymousId", e.containsKey("anonymousId"))
        assertEquals("the persisted form dropped or added a field", original.keys - "identityToken", e.keys)
        val props = e["properties"] as JSONObject
        assertEquals(3, props.getInt("level"))
        assertEquals("a caller's `traits` property was stripped", "pro", props.getJSONObject("traits").getString("plan"))
        assertFalse("the identity token reached plain SharedPreferences", (disk["event_queue"] as String).contains("tok-at-enqueue"))
    }

    @Test
    fun `a restored event gets the send-time token only for the identified user`() = runBlocking {
        val disk = mutableMapOf<String, Any?>()
        val q = EventQueue(Storage(MemoryPrefs(disk), null), flushAt = Int.MAX_VALUE)
        q.add(identified("a", "user-42"))
        q.add(identified("b", "someone-else"))
        q.persistToDisk()

        // Relaunch; identify("user-42", identityToken = "tok-42") ran again.
        val relaunched = EventQueue(
            Storage(MemoryPrefs(disk), null), flushAt = Int.MAX_VALUE,
            decorate = { decorateWithIdentity(it, "user-42", "tok-42") },
        )
        val sent = mutableListOf<Map<String, Any?>>()
        relaunched.setFlushHandler { batch -> sent += batch; FlushResult.Sent(201) }
        relaunched.flush()
        val byName = sent.associateBy { it["eventType"] }
        assertEquals("user-42", byName["a"]?.get("userId"))
        assertEquals("a restored event of the identified user got no send-time token", "tok-42", byName["a"]?.get("identityToken"))
        assertNull("another user's restored event got the token", byName["b"]?.get("identityToken"))
        assertEquals(0, relaunched.count)
    }

    @Test
    fun `a queue written by an older version without userId still loads`() {
        val disk = mutableMapOf<String, Any?>(
            "event_queue" to """[{"module":"custom","eventType":"old.one","timestamp":"t","properties":{"k":"v"},"context":{},"sessionId":"s0","consent":["analytics"]},
                {"module":"custom","eventType":"old.two","timestamp":"t","properties":{},"context":{},"sessionId":"s0","consent":["analytics"],"anonymousId":"dev-1"}]""",
        )
        val restored = EventQueue(Storage(MemoryPrefs(disk), null), flushAt = Int.MAX_VALUE).snapshot()
        assertEquals(listOf("old.one", "old.two"), restored.map { it["eventType"] })
        assertNull("a missing userId must load as absent", restored[0]["userId"])
        assertEquals("dev-1", restored[1]["anonymousId"])
        assertFalse(decorateWithIdentity(restored[0], "user-42", "tok").containsKey("identityToken"))
    }
}
