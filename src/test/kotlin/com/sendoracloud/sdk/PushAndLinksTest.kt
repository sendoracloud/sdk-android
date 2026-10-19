package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.RichTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * 4.28.0 — push registration proves the player with their own Bearer (server
 * F53), and links keep the mint's `revokeToken` so a revoke is FINAL (server F34).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PushAndLinksTest {

    @Before
    fun main() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After
    fun unmain() = Dispatchers.resetMain()

    private val unconfined = CoroutineScope(Dispatchers.Unconfined)

    // ─── push ────────────────────────────────────────────────────────────────

    private fun register(tokenProvider: suspend () -> String?): SentRequest = runBlocking {
        val transport = StubTransport()
        transport.enqueue("/push/tokens", okEnvelope(mapOf("tokenId" to "tok-1")))
        val push = SendoraCloudPush(transport, unconfined, { "user-1" }, tokenProvider)
        val done = CompletableDeferred<Result<String>>()
        push.registerToken("fcm-token") { done.complete(it) }
        assertEquals("tok-1", withTimeout(5_000) { done.await() }.getOrThrow())
        transport.sent("/push/tokens").single()
    }

    @Test
    fun `a signed-in player's push token carries their Bearer`() {
        val sent = register { "eyJ.access.token" }
        assertEquals("Bearer eyJ.access.token", sent.headers?.get("Authorization"))
        assertEquals("fcm-token", sent.body!!["token"])
    }

    @Test
    fun `no session, or an unreadable token, registers exactly as before`() {
        assertNull(register { null }.headers)
        assertNull(register { "" }.headers)
        assertNull("best-effort: a throwing provider never blocks registration", register { throw IllegalStateException("x") }.headers)
    }

    // ─── links ───────────────────────────────────────────────────────────────

    private class RichStub : RichTransport {
        val sent = mutableListOf<Triple<String, String, Map<String, Any?>?>>()
        val answers = ArrayDeque<ApiClient.RichResponse>()
        override suspend fun requestWithDetails(method: String, path: String, body: Map<String, Any?>?, extraHeaders: Map<String, String>?): ApiClient.RichResponse {
            sent += Triple(method, path, body)
            return answers.removeFirstOrNull() ?: ApiClient.RichResponse(0, null, "NETWORK", "offline")
        }
    }

    private fun ok(data: Map<String, Any?>) = ApiClient.RichResponse(200, mapOf("success" to true, "data" to data), null, null)

    private fun minted(shortcode: String, token: String?) = ok(buildMap {
        put("id", "id-$shortcode"); put("shortcode", shortcode); put("url", "https://l.example/$shortcode")
        put("fallbackUrl", "https://example.com"); token?.let { put("revokeToken", it) }
    })

    private val store = RecordingStore()
    private val rich = RichStub()
    private val links = SendoraCloudLinks(rich, "com.example", emptyList(), CoroutineScope(Dispatchers.Unconfined), store)

    private fun create(shortcode: String, token: String?): SendoraCloudLinks.LinkCreateResult = runBlocking {
        rich.answers += minted(shortcode, token)
        val done = CompletableDeferred<Result<SendoraCloudLinks.LinkCreateResult>>()
        links.create(SendoraCloudLinks.LinkCreateInput(title = "t-$shortcode")) { done.complete(it) }
        withTimeout(5_000) { done.await() }.getOrThrow()
    }

    private fun revoke(shortcode: String, token: String?): Result<SendoraCloudLinks.LinkRevokeResult> = runBlocking {
        val done = CompletableDeferred<Result<SendoraCloudLinks.LinkRevokeResult>>()
        links.revoke(shortcode, token) { done.complete(it) }
        withTimeout(5_000) { done.await() }
    }

    private fun lastBody() = rich.sent.last().third

    @Test
    fun `the mint's revokeToken is on the result and kept on the device`() {
        val r = create("abc-1", "lrt_secret1")
        assertEquals("lrt_secret1", r.revokeToken)
        assertEquals("lrt_secret1", links.storedRevokeToken("abc-1"))
        assertFalse("toString never prints it", r.toString().contains("lrt_secret1"))
        assertNull("a mint without one keeps nothing", create("abc-2", null).revokeToken)
        assertNull(links.storedRevokeToken("abc-2"))
    }

    @Test
    fun `revoke presents the kept token, reports final, and forgets it on success`() {
        create("abc-1", "lrt_secret1")
        rich.answers += ok(mapOf("shortcode" to "abc-1", "revoked" to true, "final" to true))
        val r = revoke("abc-1", null).getOrThrow()
        assertEquals(mapOf("revokeToken" to "lrt_secret1"), lastBody())
        assertTrue(r.final)
        assertNull("forgotten after success", links.storedRevokeToken("abc-1"))
    }

    @Test
    fun `an explicit token wins, and no token at all is a soft revoke`() {
        create("abc-1", "lrt_kept")
        rich.answers += ok(mapOf("shortcode" to "abc-1", "final" to true))
        revoke("abc-1", "lrt_explicit").getOrThrow()
        assertEquals(mapOf("revokeToken" to "lrt_explicit"), lastBody())

        rich.answers += ok(mapOf("shortcode" to "zzz-9", "final" to false))
        val soft = revoke("zzz-9", null).getOrThrow()
        assertEquals("no token kept → the 4.27.0 body", emptyMap<String, Any?>(), lastBody())
        assertFalse(soft.final)
    }

    @Test
    fun `a wrong token is UNAUTHORIZED and the kept token stays`() {
        create("abc-1", "lrt_kept")
        rich.answers += ApiClient.RichResponse(403, null, "FORBIDDEN", "wrong token")
        val err = revoke("abc-1", null).exceptionOrNull() as SendoraCloudLinks.LinkError
        assertEquals(SendoraCloudLinks.LinkErrorCode.UNAUTHORIZED, err.code)
        assertEquals("lrt_kept", links.storedRevokeToken("abc-1"))
    }

    @Test
    fun `an edge challenge is NETWORK, never UNAUTHORIZED`() {
        create("abc-1", "lrt_kept")
        rich.answers += ApiClient.RichResponse(403, null, "CF_CHALLENGE", "edge", retryAfterSeconds = 60, cfMitigated = true)
        val err = revoke("abc-1", null).exceptionOrNull() as SendoraCloudLinks.LinkError
        assertEquals(SendoraCloudLinks.LinkErrorCode.NETWORK, err.code)
        assertEquals("lrt_kept", links.storedRevokeToken("abc-1"))
    }

    @Test
    fun `the 4_27_0 revoke signature also presents the kept token`() = runBlocking {
        create("abc-1", "lrt_kept")
        rich.answers += ok(mapOf("shortcode" to "abc-1", "final" to true))
        val done = CompletableDeferred<Result<Unit>>()
        links.revoke("abc-1") { done.complete(it) }
        withTimeout(5_000) { done.await() }.getOrThrow()
        assertEquals(mapOf("revokeToken" to "lrt_kept"), lastBody())
    }

    @Test
    fun `at most 200 revoke tokens are kept, newest first`() {
        for (i in 0 until 205) create("l-$i", "lrt_$i")
        val kept = JSONArray(store.plain[SendoraCloudLinks.REVOKE_TOKENS_KEY] as String)
        assertEquals(200, kept.length())
        assertEquals("l-204", kept.getJSONObject(0).getString("s"))
        assertNull("the oldest fell off", links.storedRevokeToken("l-4"))
        assertEquals("lrt_5", links.storedRevokeToken("l-5"))
    }

    @Test
    fun `LinkCreateResult keeps its 4_27_0 constructor (binary compatibility)`() {
        val ctor = SendoraCloudLinks.LinkCreateResult::class.java.getConstructor(
            String::class.java, String::class.java, String::class.java, String::class.java,
            String::class.java, String::class.java, Map::class.java,
        )
        val r = ctor.newInstance("i", "s", "u", null, null, "f", emptyMap<String, Any>())
        assertNull(r.revokeToken)
    }
}
