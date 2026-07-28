package com.sendoracloud.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The other half of the corrupt-cache guard.
 *
 * The constructor deliberately KEEPS the stored refresh token when the cached
 * `auth_user` blob is unreadable — it is independently valid and the only thing
 * that can still recover the account. That is inert on its own: nothing turned
 * the kept token back into an identity, so the session stayed live with a
 * permanently null user and the next sign-in orphaned the account anyway.
 * `/token/refresh` returns the user in the very same response; the refresh path
 * now adopts it.
 *
 * Three properties are load-bearing and are pinned here:
 *  1. GAP-FILL ONLY — a refresh is a token rotation, not an identity change, so
 *     a live user is never overwritten.
 *  2. VALIDATED — `data.user` is nullable on this route (it tolerates a missing
 *     user row), so only a well-formed user is adopted.
 *  3. EMITS `SignedIn` — recovering an identity IS a state transition, while a
 *     plain rotation with a user already present must still emit nothing.
 *
 * Driving this behaviourally needs a `Context`-backed `Storage`, so it is pinned
 * by reading the source, the same way `AuthErrorCoercionTest` pins the anonymous
 * reuse guard. A live corrupt-blob recovery is the operator-owned device smoke.
 */
class RefreshUserAdoptionTest {

    private val source: String by lazy {
        val relative = "src/main/kotlin/com/sendoracloud/sdk/SendoraCloudAuth.kt"
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, relative)
            if (candidate.isFile) return@lazy candidate.readText()
            dir = dir.parentFile
        }
        ""
    }

    /** The body of `refreshAccessToken`, so a match elsewhere in the file can't
     *  satisfy an assertion about the refresh path. */
    private val refreshBody: String by lazy {
        val start = source.indexOf("private suspend fun refreshAccessToken()")
        if (start < 0) "" else source.substring(start, source.indexOf("\n    }\n", start))
    }

    @Test
    fun `the corrupt-cache guard keeps the refresh token`() {
        assertTrue("source located", source.isNotEmpty())
        val init = source.substring(source.indexOf("    init {"), source.indexOf("val currentUser"))
        assertTrue(
            "an unreadable user blob drops the user + access token, NEVER the refresh token",
            init.contains("storage.clearCachedUser()"),
        )
        assertEquals(
            "no path in the constructor may clear the refresh token",
            0,
            Regex("""clearAuthTokens\(\)""").findAll(init).count(),
        )
    }

    @Test
    fun `refresh adopts the returned user only when there is none`() {
        assertTrue("refreshAccessToken located", refreshBody.isNotEmpty())
        assertTrue(
            "gap-fill only — a live user is never overwritten by a rotation",
            refreshBody.contains("if (cachedUser == null)"),
        )
        assertTrue(
            "adopt through the parser, which rejects a null user or an empty id",
            refreshBody.contains("parseLinkedUser(response)?.let"),
        )
        assertTrue(
            "the adopted user is persisted the same way a sign-in persists one",
            refreshBody.contains("updateLocalUser(recovered)") &&
                refreshBody.contains("onIdentityChange(recovered.id)"),
        )
    }

    @Test
    fun `adoption happens after the rotated tokens are stored`() {
        assertTrue("refreshAccessToken located", refreshBody.isNotEmpty())
        // Ordering matters: the session install is what the adopted user belongs
        // to, and it is only reached past the `tokenStillCurrent` race guard.
        assertTrue(
            "the rotated refresh token is stored before the user is adopted",
            refreshBody.indexOf("storage.authRefreshToken = refreshToken") <
                refreshBody.indexOf("if (cachedUser == null)"),
        )
        assertTrue(
            "adoption sits behind the in-flight-replacement guard",
            refreshBody.indexOf("if (!tokenStillCurrent(refresh)) return@withLock null") <
                refreshBody.indexOf("if (cachedUser == null)"),
        )
    }

    @Test
    fun `a recovered identity emits SignedIn and a plain rotation emits nothing`() {
        assertTrue("refreshAccessToken located", refreshBody.isNotEmpty())
        assertTrue(
            "recovering an identity is a state transition and must reach listeners",
            refreshBody.contains("emitAuthState(AuthStateChange.SignedIn(recovered))"),
        )
        // The ONLY emission in the refresh path. A rotation that found a user
        // already present changes no state, so it must stay silent; the
        // dead-token branch reports itself through wipeLocalIdentity instead.
        assertEquals(
            "emitAuthState sites inside refreshAccessToken",
            1,
            Regex("""emitAuthState\(""").findAll(refreshBody).count(),
        )
    }
}
