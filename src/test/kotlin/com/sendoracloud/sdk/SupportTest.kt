package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.AuthTransport
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.URLDecoder

/**
 * 4.27.0 (s58.376) — support parity with RN 1.42.0 / iOS 5.5.0, through a recording transport.
 *
 * Mutations that must turn this red: drop the Bearer on createTicket; swallow a refusal into an empty list; send a
 * support call with no session; put the token in the query; stop dropping invalid metadata; let a non-hex accent in.
 */
class SupportTest {
    private class Rec(val method: String, val path: String, val body: Map<String, Any?>?, val headers: Map<String, String>?)

    private class FakeTransport : AuthTransport {
        val calls = mutableListOf<Rec>()
        val replies = mutableMapOf<String, Map<String, Any?>?>()
        override suspend fun post(path: String, body: Map<String, Any?>, extraHeaders: Map<String, String>?): Map<String, Any?>? {
            calls += Rec("POST", path, body, extraHeaders); return replies["POST $path"]
        }
        override suspend fun get(path: String, extraHeaders: Map<String, String>?): Map<String, Any?>? {
            calls += Rec("GET", path, null, extraHeaders); return replies["GET $path"]
        }
        override suspend fun delete(path: String, extraHeaders: Map<String, String>?): Map<String, Any?>? {
            calls += Rec("DELETE", path, null, extraHeaders); return replies["DELETE $path"]
        }
    }

    private fun ok(data: Any?) = mapOf("success" to true, "data" to data)
    private fun refused(status: Int, code: String) =
        mapOf("success" to false, "error" to mapOf("code" to code, "message" to code, "status" to status))

    private fun support(token: String?, t: FakeTransport) = SendoraCloudSupport(
        transportProvider = { t },
        tokenProvider = { token },
        contextProvider = { mapOf("os" to "Android", "sdk" to "sendora-android@test") },
    )

    @Test fun listMyTickets_sendsTheBearer_andReturnsTheTickets() = runTest {
        val t = FakeTransport()
        t.replies["GET /widgets/w1/my-tickets"] = ok(listOf(mapOf(
            "id" to "t1", "subject" to "Stuck", "status" to "pending", "priority" to "normal",
            "createdAt" to "x", "updatedAt" to "y", "resolvedAt" to null, "unread" to true,
        )))
        val list = support("tok-1", t).listMyTickets("w1")
        assertEquals(listOf(SendoraMyTicketSummary("t1", "Stuck", "pending", "normal", "x", "y", null, true)), list)
        assertEquals("Bearer tok-1", t.calls.single().headers?.get("Authorization"))
    }

    @Test fun aRefusalThrowsTheServersCode_neverAnEmptyList() = runTest {
        val t = FakeTransport()
        t.replies["GET /widgets/w1/my-tickets"] = refused(403, "PROJECT_MISMATCH")
        try {
            support("tok-1", t).listMyTickets("w1")
            fail("expected a refusal")
        } catch (e: SendoraSupportException) {
            assertEquals("PROJECT_MISMATCH", e.code)
            assertEquals(403, e.status)
        }
    }

    @Test fun noSession_throwsNotSignedIn_andSendsNothing() = runTest {
        val t = FakeTransport()
        try {
            support(null, t).getMyTicket("w1", "t1")
            fail("expected NOT_SIGNED_IN")
        } catch (e: SendoraSupportException) {
            assertEquals("NOT_SIGNED_IN", e.code)
        }
        assertTrue(t.calls.isEmpty())
    }

    @Test fun getMyTicket_andReply() = runTest {
        val t = FakeTransport()
        t.replies["GET /widgets/w1/my-tickets/t1"] = ok(mapOf(
            "id" to "t1", "subject" to "s", "body" to "b", "status" to "open", "priority" to "normal",
            "createdAt" to "x", "updatedAt" to "y",
            "replies" to listOf(mapOf("id" to "r0", "body" to "Hi", "authorType" to "agent", "createdAt" to "z")),
        ))
        t.replies["POST /widgets/w1/my-tickets/t1/replies"] = ok(mapOf("id" to "r1", "createdAt" to "z", "reopened" to true))
        val s = support("tok-1", t)
        assertEquals(listOf(SendoraMyTicketReply("r0", "Hi", "agent", "z")), s.getMyTicket("w1", "t1").replies)
        assertTrue(s.replyToMyTicket("w1", "t1", "Still broken").reopened)
        assertEquals("Still broken", t.calls.last().body?.get("body"))
    }

    @Test fun createTicket_sendsTheTokenWhenThereIsOne_andSanitisesMetadata() = runTest {
        val created = ok(mapOf("id" to "t9", "subject" to "s", "status" to "open", "priority" to "normal", "userIdVerified" to true))
        val a = FakeTransport().also { it.replies["POST /support/tickets"] = created }
        val ticket = support("tok-2", a).createTicket("Refund", "Charged twice",
            metadata = mapOf("plan" to "pro", "level" to 40, "nested" to mapOf("a" to 1), "<bad>" to "x"))
        assertTrue(ticket.userIdVerified)
        assertEquals("Bearer tok-2", a.calls.single().headers?.get("Authorization"))
        @Suppress("UNCHECKED_CAST")
        assertEquals(setOf("plan", "level"), (a.calls.single().body?.get("metadata") as Map<String, Any?>).keys)

        val b = FakeTransport().also { it.replies["POST /support/tickets"] = created }
        support(null, b).createTicket("Refund", "Charged twice")
        assertNull(b.calls.single().headers)
    }

    @Test fun getUnreadCount_isZeroWhenSignedOutOrRefused() = runTest {
        val t = FakeTransport()
        t.replies["GET /widgets/w1/my-tickets/unread-count"] = ok(mapOf("count" to 3))
        assertEquals(3, support("tok-1", t).getUnreadCount("w1"))
        assertEquals(0, support(null, t).getUnreadCount("w1"))
        t.replies["GET /widgets/w1/my-tickets/unread-count"] = refused(500, "INTERNAL_ERROR")
        assertEquals(0, support("tok-1", t).getUnreadCount("w1"))
    }

    @Test fun sanitizeMetadata_backendRules() {
        val many = (0 until 40).associate { "k$it" to it as Any? }
        assertEquals(30, SendoraCloudSupport.sanitizeMetadata(many).size)
        val out = SendoraCloudSupport.sanitizeMetadata(mapOf(
            "ok" to true, "n" to 1.5, "none" to null, "inf" to Double.POSITIVE_INFINITY,
            "arr" to listOf(1), "s" to "x".repeat(2000),
        ))
        assertEquals(setOf("ok", "n", "none", "s"), out.keys)
        assertEquals(1000, (out["s"] as String).length)
    }

    @Test fun contactUrl_tokenAndMetadataInTheFragment_accentOnlyWhenHex() {
        val url = SendoraCloudSupport.contactUrl("https://go.test", "w1", "auto", null, null, "u1", false,
            "#22c55e", "tok.a+b", mapOf("plan" to "pro & co"))
        val query = url.substringAfter("?").substringBefore("#")
        val fragment = url.substringAfter("#")
        assertTrue(query.contains("accent=%2322c55e"))
        assertFalse(query.contains("tok"))
        // The page decodes the fragment with URLSearchParams (+ = space, %2B = +).
        val parts = fragment.split("&").associate { it.substringBefore("=") to URLDecoder.decode(it.substringAfter("="), "UTF-8") }
        assertEquals("tok.a+b", parts["access"])
        assertEquals("pro & co", JSONObject(parts["metadata"]!!).getString("plan"))

        val bad = SendoraCloudSupport.contactUrl("https://go.test", "w1", "auto", null, null, null, false,
            "red;}</style>", null, emptyMap())
        assertFalse(bad.contains("#"))
        assertFalse(bad.contains("accent"))
    }
}
