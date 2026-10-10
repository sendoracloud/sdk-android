package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.AuthKeys
import com.sendoracloud.sdk.internal.AuthStore
import com.sendoracloud.sdk.internal.AuthTransport
import com.sendoracloud.sdk.internal.RefreshCron
import kotlinx.coroutines.CompletableDeferred
import org.json.JSONObject
import java.io.File
import java.util.Base64

/**
 * The JVM doubles the ADR-033 suites drive the auth machine with — no Context,
 * no network, no Android.
 *
 *  - [RecordingStore] records EVERY write (tier, key, value) so "zero storage
 *    writes" and "exactly these keys" are asserted on what happened, byte for
 *    byte, never on the source text.
 *  - [StubTransport] records every request (path, body, headers) and answers
 *    from scripted handlers, so INV-3 ("the body carries no guest hint") and
 *    "no network" rows are read off what was SENT. A handler may suspend on a
 *    gate, which is how the refresh/sign-in interleavings are driven.
 *  - [RecordingCron] records arm/disarm instead of ticking.
 */

internal data class StoreWrite(val tier: String, val key: String, val value: Any?)

internal class RecordingStore(override val isSecureAvailable: Boolean = true) : AuthStore {
    val secure = linkedMapOf<String, Any>()
    val plain = linkedMapOf<String, Any>()
    val writes = mutableListOf<StoreWrite>()

    fun snapshot(): Map<String, Any?> = (secure.mapKeys { "secure:" + it.key } + plain.mapKeys { "plain:" + it.key })

    override fun secureGet(key: String): String? = secure[key] as? String
    override fun securePut(key: String, value: String?) {
        writes += StoreWrite("secure", key, value)
        if (value == null) secure.remove(key) else secure[key] = value
    }
    override fun secureGetLong(key: String): Long = (secure[key] as? Long) ?: 0L
    override fun securePutLong(key: String, value: Long) {
        writes += StoreWrite("secure", key, value)
        if (value <= 0L) secure.remove(key) else secure[key] = value
    }
    override fun plainGet(key: String): String? = plain[key] as? String
    override fun plainPut(key: String, value: String?) {
        writes += StoreWrite("plain", key, value)
        if (value == null) plain.remove(key) else plain[key] = value
    }

    /** Seed the four frozen keys the way a 4.25.0 left them (no `auth_session`). */
    fun seedLegacySession(user: SendoraCloudAuthUser?, access: String?, refresh: String?, expiresAt: Long) {
        user?.let { secure[AuthKeys.USER] = userJson(it) }
        access?.let { secure[AuthKeys.ACCESS] = it }
        refresh?.let { secure[AuthKeys.REFRESH] = it }
        if (expiresAt > 0) secure[AuthKeys.EXPIRES] = expiresAt
    }

    fun seedHeld(index: Int, json: String) { secure[AuthKeys.HELD_SLOT_KEYS[index]] = json }

    fun heldJson(index: Int): JSONObject? = (secure[AuthKeys.HELD_SLOT_KEYS[index]] as? String)?.let { JSONObject(it) }

    fun writesTo(key: String) = writes.filter { it.key == key }
}

internal data class SentRequest(val method: String, val path: String, val body: Map<String, Any?>?, val headers: Map<String, String>?)

internal class StubTransport : AuthTransport {
    val requests = mutableListOf<SentRequest>()
    private val handlers = mutableMapOf<String, suspend (SentRequest) -> Map<String, Any?>?>()
    private val queues = mutableMapOf<String, ArrayDeque<Map<String, Any?>?>>()

    /** Script a handler for a path (method-agnostic); it may suspend. */
    fun on(path: String, handler: suspend (SentRequest) -> Map<String, Any?>?) { handlers[path] = handler }

    /** Script FIFO canned answers for a path; `null` = transport failure (timeout / offline). */
    fun enqueue(path: String, vararg responses: Map<String, Any?>?) {
        queues.getOrPut(path) { ArrayDeque() }.addAll(responses)
    }

    fun sent(path: String) = requests.filter { it.path == path }
    fun count(path: String) = sent(path).size

    private suspend fun dispatch(req: SentRequest): Map<String, Any?>? {
        requests += req
        handlers[req.path]?.let { return it(req) }
        queues[req.path]?.let { q -> if (q.isNotEmpty()) return q.removeFirst() }
        return null
    }

    override suspend fun post(path: String, body: Map<String, Any?>, extraHeaders: Map<String, String>?) = dispatch(SentRequest("POST", path, body, extraHeaders))
    override suspend fun get(path: String, extraHeaders: Map<String, String>?) = dispatch(SentRequest("GET", path, null, extraHeaders))
    override suspend fun delete(path: String, extraHeaders: Map<String, String>?) = dispatch(SentRequest("DELETE", path, null, extraHeaders))
}

internal class RecordingCron : RefreshCron {
    var arms = 0
    var disarms = 0
    var tick: (suspend () -> Unit)? = null
    override val isArmed: Boolean get() = tick != null
    override fun arm(tick: suspend () -> Unit) { if (this.tick != null) return; arms++; this.tick = tick }
    override fun disarm() { if (tick != null) disarms++; tick = null }
}

/** A gate a scripted handler can park on, to interleave two in-flight calls deterministically. */
internal class Gate {
    private val d = CompletableDeferred<Unit>()
    val opened = CompletableDeferred<Unit>()
    suspend fun await() { opened.complete(Unit); d.await() }
    fun release() { d.complete(Unit) }
}

// ─── fixtures ───────────────────────────────────────────────────────────────

internal const val PROJECT_A = "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b"
internal const val PROJECT_B = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9"

/** A LITERAL JWT (unsigned, like the fixture's): header.payload.signature with the given claims. */
internal fun jwt(sub: String, sid: String?, project: Any? = PROJECT_A, projectPresent: Boolean = true, anonymous: Boolean = true, exp: Long = 1_760_000_900L): String {
    val payload = JSONObject()
    payload.put("iss", "https://api.sendoracloud.com/api/v1/auth-service/a1b2c3d4-e5f6-4789-8abc-def012345678")
    payload.put("sub", sub)
    if (projectPresent) payload.put("project", project ?: JSONObject.NULL)
    payload.put("is_anonymous", anonymous)
    sid?.let { payload.put("sid", it) }
    payload.put("iat", 1_760_000_000L)
    payload.put("exp", exp)
    val enc = Base64.getUrlEncoder().withoutPadding()
    val header = enc.encodeToString("""{"alg":"RS256","typ":"JWT","kid":"default"}""".toByteArray())
    return header + "." + enc.encodeToString(payload.toString().toByteArray()) + ".fixture-signature"
}

internal fun user(id: String, anonymous: Boolean, email: String? = null, project: String? = PROJECT_A): SendoraCloudAuthUser =
    SendoraCloudAuthUser(id = id, email = email, emailVerified = false, name = null, isAnonymous = anonymous, project = project, projectKnown = true)

internal fun userJson(u: SendoraCloudAuthUser): String = JSONObject().apply {
    put("id", u.id); put("email", u.email ?: JSONObject.NULL); put("emailVerified", u.emailVerified)
    put("name", JSONObject.NULL); put("isAnonymous", u.isAnonymous)
    put("signupMethod", JSONObject.NULL); put("lastLoginMethod", JSONObject.NULL)
    if (u.projectKnown) put("project", u.project ?: JSONObject.NULL)
}.toString()

internal fun userMap(u: SendoraCloudAuthUser): Map<String, Any?> = mapOf(
    "id" to u.id, "email" to u.email, "emailVerified" to u.emailVerified, "name" to u.name,
    "isAnonymous" to u.isAnonymous, "signupMethod" to null, "lastLoginMethod" to null, "project" to u.project,
)

/** A `{ success, data: { user, tokens } }` envelope, as the backend sends it. */
internal fun sessionEnvelope(
    u: SendoraCloudAuthUser,
    access: String,
    refresh: String,
    expiresIn: Long = 900,
    extra: Map<String, Any?> = emptyMap(),
): Map<String, Any?> = mapOf(
    "success" to true,
    "data" to (mapOf(
        "user" to userMap(u),
        "tokens" to mapOf("accessToken" to access, "refreshToken" to refresh, "expiresIn" to expiresIn, "tokenType" to "Bearer"),
        "csrfToken" to "csrf",
    ) + extra),
)

/** `/token/refresh` — the rotated trio NESTED under `data.tokens` (s58.76). */
internal fun refreshEnvelope(u: SendoraCloudAuthUser?, access: String, refresh: String, expiresIn: Long = 900): Map<String, Any?> = mapOf(
    "success" to true,
    "data" to mapOf(
        "user" to u?.let { userMap(it) },
        "tokens" to mapOf("accessToken" to access, "refreshToken" to refresh, "expiresIn" to expiresIn),
        "csrfToken" to "csrf",
    ),
)

internal fun errorEnvelope(code: String, status: Int, message: String = code, details: Map<String, Any?>? = null): Map<String, Any?> = mapOf(
    "success" to false,
    "error" to (mapOf("code" to code, "message" to message, "status" to status) + (details?.let { mapOf("details" to it) } ?: emptyMap())),
)

internal fun deadRefresh(endReason: String?): Map<String, Any?> =
    errorEnvelope("INVALID_REFRESH_TOKEN", 401, details = mapOf("retryAfterSeconds" to 60) + (endReason?.let { mapOf("endReason" to it) } ?: emptyMap()))

internal fun okEnvelope(data: Map<String, Any?> = emptyMap()): Map<String, Any?> = mapOf("success" to true, "data" to data)

internal fun heldSlotJson(userId: String, refresh: String, heldAt: Long, project: String? = PROJECT_A, autoRestore: Boolean = true, sid: String? = "sid-$userId", tokenAtHold: String = refresh): String =
    JSONObject().apply {
        put("v", 1); put("userId", userId); put("sid", sid ?: JSONObject.NULL); put("refreshToken", refresh)
        put("tokenAtHold", tokenAtHold); put("heldAt", heldAt); put("project", project ?: JSONObject.NULL); put("autoRestore", autoRestore)
    }.toString()

/** Walk up from the module directory to the monorepo root. */
internal fun repoFile(relative: String): File? {
    var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
    while (dir != null) {
        val candidate = File(dir, relative)
        if (candidate.isFile) return candidate
        dir = dir.parentFile
    }
    return null
}

/** Build a machine around the doubles with a synchronous event recorder. */
internal class Rig(
    val store: RecordingStore = RecordingStore(),
    val transport: StubTransport = StubTransport(),
    val cron: RecordingCron = RecordingCron(),
    expectedProjectId: String? = null,
    projectId: String? = null,
    autoRestoreHeldGuest: Boolean = true,
    var now: Long = 1_760_000_000_000L,
) {
    val events = mutableListOf<AuthStateChange>()
    val identityChanges = mutableListOf<String?>()
    val wipes = mutableListOf<AuthWipeEffects>()
    var withheldHooks = 0
    /** Fire-and-forget calls run INLINE so a revoke / hold report is visible to the assertion that follows. */
    val backgroundRan = mutableListOf<Unit>()
    val auth: SendoraCloudAuth = SendoraCloudAuth(
        client = transport,
        storage = store,
        onIdentityChange = { identityChanges += it },
        onAnonymousWipe = { wipes += it },
        machine = AuthMachineConfig(projectId = projectId, expectedProjectId = expectedProjectId, autoRestoreHeldGuest = autoRestoreHeldGuest),
        onIdentityWithheld = { withheldHooks++ },
        cron = cron,
        clock = { now },
        background = { block -> kotlinx.coroutines.runBlocking { block() }; backgroundRan += Unit },
        eventSink = { events += it },
    )
    val eventNames get() = events.map { it.event }
    fun writesSince(mark: Int) = store.writes.drop(mark)
}
