package com.sendoracloud.sdk.internal

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Response-envelope parsing at the transport boundary.
 *
 * `org.json` returns `JSONObject` / `JSONArray` for nested values, so a body
 * converted only at the top level leaves `data` as a `JSONObject` — and every
 * `as? Map<String, Any?>` cast the SDK uses to read it silently yields null.
 * `SendoraCloudAuth.parseSuccess` reads `data` → `user` → `tokens` through
 * exactly those casts, so it could never return a user and every sign-in
 * failed as "Malformed response". The same shape breaks deferred attribution,
 * geofences, the push tokenId read, and the passkey start/finish envelopes.
 *
 * These assertions use the cast expressions the production code performs,
 * against real backend envelope shapes, so a regression to a shallow
 * conversion fails here instead of on a device.
 */
class ApiClientEnvelopeTest {

    /** The `POST /auth-service/login` success envelope, as the backend sends it. */
    private val loginSuccess = """
        {
          "success": true,
          "data": {
            "user": {
              "id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
              "email": null,
              "emailVerified": false,
              "name": null,
              "isAnonymous": false,
              "signupMethod": "anonymous",
              "lastLoginMethod": "playgames"
            },
            "tokens": {
              "accessToken": "eyJhbGciOiJSUzI1NiJ9.payload.sig",
              "refreshToken": "rt_9f8e7d6c",
              "expiresIn": 900,
              "tokenType": "Bearer"
            },
            "retiredAnonUserId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "reactivatedFromDeletion": true
          }
        }
    """.trimIndent()

    @Test
    fun `parseSuccess casts reach the user and tokens`() {
        val body = parseJsonBody(loginSuccess)
        assertNotNull("body parsed", body)

        @Suppress("UNCHECKED_CAST")
        val data = body?.get("data") as? Map<String, Any?>
        assertNotNull("data is a Map, not a JSONObject", data)

        @Suppress("UNCHECKED_CAST")
        val user = data?.get("user") as? Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val tokens = data?.get("tokens") as? Map<String, Any?>
        assertNotNull("user is a Map", user)
        assertNotNull("tokens is a Map", tokens)

        assertEquals("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", user?.get("id") as? String)
        assertEquals("eyJhbGciOiJSUzI1NiJ9.payload.sig", tokens?.get("accessToken") as? String)
        assertEquals("rt_9f8e7d6c", tokens?.get("refreshToken") as? String)
        assertEquals(900L, (tokens?.get("expiresIn") as? Number)?.toLong())
        assertEquals("playgames", user?.get("lastLoginMethod") as? String)
    }

    @Test
    fun `persist reads the takeover and deletion-cancelled signals`() {
        val body = parseJsonBody(loginSuccess)
        @Suppress("UNCHECKED_CAST")
        val data = body?.get("data") as? Map<String, Any?>
        assertEquals(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            data?.get("retiredAnonUserId") as? String,
        )
        assertEquals(true, data?.get("reactivatedFromDeletion") as? Boolean)
    }

    @Test
    fun `a JSON null becomes a Kotlin null, never the NULL sentinel`() {
        val body = parseJsonBody(loginSuccess)
        @Suppress("UNCHECKED_CAST")
        val user = (body?.get("data") as? Map<String, Any?>)?.get("user") as? Map<String, Any?>
        // JSONObject.NULL is truthy and is NOT Kotlin null — an untranslated
        // sentinel would sail through `as? String` as a non-null value.
        assertNull("email", user?.get("email"))
        assertTrue("key present", user?.containsKey("email") == true)
    }

    @Test
    fun `parseError reaches the code, message and retryAfterSeconds hint`() {
        val locked = """
            {
              "success": false,
              "error": {
                "code": "ACCOUNT_LOCKED",
                "message": "Account is temporarily locked. Please try again later.",
                "details": { "retryAfterSeconds": 873 }
              }
            }
        """.trimIndent()
        val body = parseJsonBody(locked)?.withErrorStatus(403)

        @Suppress("UNCHECKED_CAST")
        val error = body?.get("error") as? Map<String, Any?>
        assertNotNull("error is a Map", error)
        assertEquals("ACCOUNT_LOCKED", error?.get("code") as? String)
        assertEquals(403, (error?.get("status") as? Number)?.toInt())

        @Suppress("UNCHECKED_CAST")
        val details = error?.get("details") as? Map<String, Any?>
        assertEquals(873, (details?.get("retryAfterSeconds") as? Number)?.toInt())
    }

    @Test
    fun `withErrorStatus does not invent an error object`() {
        // An absent `error` is what makes a caller fall back to its own default
        // code, and shipped apps string-match those codes.
        val body = parseJsonBody("""{"success":false}""")?.withErrorStatus(500)
        assertNull(body?.get("error"))
        assertEquals(false, body?.get("success") as? Boolean)
    }

    @Test
    fun `listLinkedIdentities reads an array of objects`() {
        val identities = """
            {
              "success": true,
              "data": {
                "identities": [
                  { "provider": "playgames", "email": null, "linkedAt": "2026-07-20T10:00:00.000Z" },
                  { "provider": "google", "email": "a@b.co", "linkedAt": "2026-07-24T09:30:00.000Z" }
                ],
                "hasPassword": false
              }
            }
        """.trimIndent()
        val body = parseJsonBody(identities)

        @Suppress("UNCHECKED_CAST")
        val data = body?.get("data") as? Map<String, Any?>
        val list = data?.get("identities") as? List<*>
        assertNotNull("identities is a List, not a JSONArray", list)
        assertEquals(2, list?.size)

        @Suppress("UNCHECKED_CAST")
        val first = list?.get(0) as? Map<String, Any?>
        assertNotNull("array element is a Map", first)
        assertEquals("playgames", first?.get("provider") as? String)
        assertNull("email", first?.get("email"))
        assertEquals(false, data?.get("hasPassword") as? Boolean)
    }

    @Test
    fun `geofence and session list envelopes read as a top-level array`() {
        val body = parseJsonBody("""{"success":true,"data":[{"id":"g1","radius":150}]}""")
        val data = body?.get("data") as? List<*>
        assertNotNull("data is a List", data)
        @Suppress("UNCHECKED_CAST")
        val row = data?.filterIsInstance<Map<String, Any>>()?.firstOrNull()
        assertEquals("g1", row?.get("id"))
    }

    @Test
    fun `deeply nested values convert all the way down`() {
        val body = parseJsonBody("""{"a":{"b":{"c":[{"d":"deep"}]}}}""")
        @Suppress("UNCHECKED_CAST")
        val a = body?.get("a") as? Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val b = a?.get("b") as? Map<String, Any?>
        val c = b?.get("c") as? List<*>
        @Suppress("UNCHECKED_CAST")
        val d = c?.get(0) as? Map<String, Any?>
        assertEquals("deep", d?.get("d") as? String)
    }

    @Test
    fun `an unparseable body yields null rather than throwing`() {
        assertNull(parseJsonBody("<html>502 Bad Gateway</html>"))
        assertNull(parseJsonBody(""))
    }

    @Test
    fun `unwrapJson leaves scalars alone`() {
        assertEquals("s", unwrapJson("s"))
        assertEquals(1, unwrapJson(1))
        assertEquals(true, unwrapJson(true))
        assertNull(unwrapJson(JSONObject.NULL))
        assertNull(unwrapJson(null))
    }
}
