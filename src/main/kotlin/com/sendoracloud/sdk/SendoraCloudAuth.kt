package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.ApiClient
import com.sendoracloud.sdk.internal.SendoraCloudLogger
import com.sendoracloud.sdk.internal.Storage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import kotlin.random.Random

/**
 * Auth Service surface for the Android SDK.
 *
 * Three flows mirroring the web + iOS + RN SDKs:
 *   - signInAnonymously()        — returns the anonymous session this
 *                                  device already holds; only mints a
 *                                  new one (POST /auth-service/anonymous)
 *                                  when there is none.
 *   - signUp(email, password)    — upgrades the same row in place
 *                                  when called from an anonymous
 *                                  session; otherwise creates a
 *                                  fresh account.
 *   - signIn(email, password)    — logs into an existing account.
 *                                  The prior identity is replaced
 *                                  only once the response validates
 *                                  as a success.
 *   - signOut()                  — wipe FIRST, fire-and-forget revoke.
 *                                  User is logged out on device even
 *                                  if the network call hangs.
 *
 * All public ops are serialized through a single Mutex so a UI
 * double-submit can't mint two anonymous users or interleave a
 * signIn + signOut. Response payloads are validated non-empty
 * before persisting — a malformed/MitM'd response can't install an
 * `id = ""` user.
 *
 * INVARIANT — a failed auth attempt leaves the caller exactly as it
 * found them. Every credentialed sign-in reads the anonymous refresh
 * token into a local, makes the call, validates the response, and
 * ONLY THEN wipes + persists. For an anonymous user that refresh
 * token is the only durable handle on the account, so a wipe that
 * runs ahead of a fallible call and isn't followed by a successful
 * persist orphans the account permanently — offline that isn't a
 * race, it's a guarantee.
 *
 * Tokens persist in `EncryptedSharedPreferences` only. If secure
 * storage is unavailable, persistence FAILS instead of falling back
 * to plaintext SharedPreferences.
 */

data class SendoraCloudAuthUser(
    val id: String,
    val email: String?,
    val emailVerified: Boolean,
    val name: String?,
    val isAnonymous: Boolean,
    /**
     * How this account was FIRST created (`signupMethod`, immutable) and how it
     * MOST RECENTLY authenticated (`lastLoginMethod`). Free-form provider tokens
     * (`password`/`anonymous`/`google`/`apple`/`gamecenter`/`playgames`/
     * `magic_link`/`passkey`/`oidc`/…). Read-only, display-only — never an
     * authorization signal. `null` against a backend older than s58.266, or for a
     * row created before it (backfilled on next sign-in). Defaulted so cached
     * users from a pre-4.8.0 build still construct. sdk-android 4.8.0+.
     */
    val signupMethod: String? = null,
    val lastLoginMethod: String? = null,
)

/**
 * Closed set of auth failure categories (4.12.0). Branch on
 * [SendoraCloudAuthError.kind] instead of matching the ~20 raw codes the
 * backend and the transport between them can produce.
 *
 * Pairs with the guarantee this release introduces: a failed auth attempt never
 * changes the local session. An offline sign-in, a mistyped OTP, a dismissed
 * Credential Manager sheet and a 429 all leave [SendoraCloudAuth.currentUser]
 * and the stored refresh token exactly as they were.
 */
/**
 * What a credentialed sign-in should do when the credential you present already
 * belongs to an account (4.15.0).
 *
 * **You usually want the default — pass null.** Since 4.17.0 the default is
 * safe by construction: it adopts the other account silently when nothing would
 * be destroyed, and refuses when something would be.
 *
 * - **Fresh install / no guest session** → nothing to lose, so it adopts. This
 *   is the reinstall-recovery path — a Play Games identity survives a reinstall
 *   server-side, so the collision is usually the SAME person's earlier account,
 *   and they get it back. Never refused.
 * - **Live guest session** → adopting would retire it (**its row is deleted**
 *   and the device-takeover listener fires). Refused with
 *   [SendoraCloudAuthError.CredentialInUse] so you can ask the player.
 *
 * Override in either direction: [ADOPT] always adopts, even when it deletes the
 * guest account (pre-4.15.0 behaviour); [REJECT] always fails on a collision,
 * even a harmless one.
 *
 * ⚠ A refusal blocks the switch; it does not merge the two accounts. To offer "use
 * my other account", catch the error and re-call with [ADOPT], then migrate
 * your own data from the takeover listener's `retiredAnonUserId`.
 */
enum class CredentialCollisionPolicy(val wire: String) {
    ADOPT("adopt"),
    REJECT("reject"),
}

enum class SendoraCloudAuthErrorKind {
    NETWORK,
    SERVER,
    RATE_LIMITED,
    INVALID_CREDENTIAL,
    ACCOUNT_LOCKED,
    CREDENTIAL_IN_USE,
    ALREADY_IDENTIFIED,
    CANCELLED,
    CONFIG,
    UNKNOWN;

    /** True when retrying the SAME input can plausibly succeed later. */
    val retryable: Boolean
        get() = this == NETWORK || this == SERVER || this == RATE_LIMITED || this == ACCOUNT_LOCKED

    companion object {
        /**
         * Map a raw error code (+ HTTP status when known) onto the taxonomy.
         * Unknown codes fall back to a status-derived kind, then [UNKNOWN] — a
         * backend that adds a code this SDK has never heard of still classifies
         * sanely instead of being reported as retryable.
         */
        fun classify(code: String?, status: Int? = null): SendoraCloudAuthErrorKind {
            when (code) {
                "NETWORK_ERROR", "NETWORK_TIMEOUT" -> return NETWORK
                "PARSE_ERROR" -> return SERVER
                "RATE_LIMITED", "RATE_LIMIT", "RATE_LIMIT_EXCEEDED", "QUOTA_EXCEEDED" -> return RATE_LIMITED
                "ACCOUNT_LOCKED" -> return ACCOUNT_LOCKED
                "CREDENTIAL_IN_USE" -> return CREDENTIAL_IN_USE
                "NOT_ANONYMOUS", "FORBIDDEN_NON_ANONYMOUS" -> return ALREADY_IDENTIFIED
                "PASSKEY_USER_CANCELLED", "GAME_CENTER_CANCELLED",
                "PLAY_GAMES_CANCELLED", "SSO_CANCELLED" -> return CANCELLED
                "GAME_CENTER_UNAVAILABLE", "PLAY_GAMES_UNAVAILABLE",
                "ENTITLEMENT_ERROR", "tier_required" -> return CONFIG
                "UNAUTHORIZED", "INVALID_CREDENTIALS", "INVALID_REFRESH_TOKEN",
                "EMAIL_OTP_INVALID", "MAGIC_LINK_INVALID", "PASSKEY_RP_MISMATCH",
                "NOT_SIGNED_IN" -> return INVALID_CREDENTIAL
            }
            if (status != null) {
                if (status == 429) return RATE_LIMITED
                if (status >= 500) return SERVER
                // 401/403/404/409/422 on an auth attempt all mean "this
                // credential/input will not work as-is" — the app must collect
                // something new.
                if (status >= 400) return INVALID_CREDENTIAL
            }
            return UNKNOWN
        }
    }
}

sealed class SendoraCloudAuthError(
    message: String,
    /**
     * Category of the failure — the field to branch on (4.12.0). See
     * [SendoraCloudAuthErrorKind]. Derived from [code] (+ HTTP status when
     * known); the error CLASSES are unchanged, so existing `when (err)` /
     * `is SendoraCloudAuthError.Unauthorized` checks keep working.
     */
    val kind: SendoraCloudAuthErrorKind,
    /** Raw backend/transport code when one reached the SDK, else null. */
    val code: String? = null,
    /** HTTP status when the failure came from a response (absent when offline). */
    val status: Int? = null,
    /**
     * Seconds to wait before retrying, when the server told us (429 backoff, or
     * an ACCOUNT_LOCKED cool-off). Absent means "no server-provided hint" — for
     * [SendoraCloudAuthErrorKind.ACCOUNT_LOCKED] specifically, absent means the
     * lock does NOT expire on its own and needs support.
     */
    val retryAfterSeconds: Int? = null,
) : Throwable(message) {
    /** True when retrying the SAME input can plausibly succeed later. */
    val retryable: Boolean get() = kind.retryable

    class EmailAlreadyTaken(message: String, code: String? = null, status: Int? = null) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.INVALID_CREDENTIAL, code, status)
    /** `signUp()` on a session already signed in with an identity (ADR-030 §4).
     *  Use `linkEmailPassword()` / `linkGoogle()` / … to add a credential to THIS
     *  account, or sign out first — do not create a second account. */
    class AlreadyIdentified(message: String, code: String? = null, status: Int? = null) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.ALREADY_IDENTIFIED, code, status)
    /** A credential passed to `link*()` is already attached to a DIFFERENT
     *  account (ADR-030 §2). Sendora never auto-merges two real accounts. */
    class CredentialInUse(message: String, code: String? = null, status: Int? = null) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CREDENTIAL_IN_USE, code, status)
    class Unauthorized(message: String, code: String? = null, status: Int? = null) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.INVALID_CREDENTIAL, code, status)
    class Network(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.NETWORK, "NETWORK_ERROR")
    class SecureStorageUnavailable(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CONFIG, "SECURE_STORAGE_UNAVAILABLE")
    class Unknown(
        message: String,
        code: String? = null,
        status: Int? = null,
        retryAfterSeconds: Int? = null,
        kind: SendoraCloudAuthErrorKind = SendoraCloudAuthErrorKind.classify(code, status),
    ) : SendoraCloudAuthError(message, kind, code, status, retryAfterSeconds)
}

/**
 * Coerce anything thrown out of an auth operation into a typed
 * [SendoraCloudAuthError], so every failure a caller sees carries a
 * [SendoraCloudAuthError.kind] it can branch on.
 *
 * ⚠ The default MUST stay non-fatal. That is what makes the one-code
 * dead-refresh allow-list safe rather than merely lucky: an unmapped failure
 * classifies as [SendoraCloudAuthErrorKind.UNKNOWN] — not retryable, but never
 * "your token is dead" — so a new failure mode can only become session-fatal
 * through a deliberate edit. Firebase enforces the same rule at its HTTP
 * boundary.
 *
 * [CancellationException] never reaches here: every call site rethrows it
 * first. Turning a cancellation into a `Result.failure` would let a coroutine
 * the caller already abandoned run on and report, breaking every
 * structured-concurrency guarantee above the SDK.
 *
 * Android's transport does not surface a timeout as a throwable —
 * `ApiClient` wraps each call in `withTimeoutOrNull` and hands back null, which
 * [SendoraCloudAuth.parseError] already turns into
 * [SendoraCloudAuthError.Network]. The timeout family is mapped anyway because
 * the fallible work around the transport is not the transport: an
 * EncryptedSharedPreferences read against an invalidated Keystore key, a
 * host-supplied `onAnonymousWipe`. A stalled carrier network is the case an
 * offline-first app most needs to branch on, so it must not classify as
 * `UNKNOWN`.
 */
internal fun asAuthError(t: Throwable): SendoraCloudAuthError = when (t) {
    // Already typed — including EmailAlreadyTaken / AlreadyIdentified /
    // CredentialInUse, which shipped apps match by CLASS. Rewrapping those
    // would silently break every `is`-check written against them.
    is SendoraCloudAuthError -> t
    // SocketTimeoutException extends InterruptedIOException, so both the
    // connect and the read timeout land here.
    is java.io.InterruptedIOException,
    is java.util.concurrent.TimeoutException,
    -> SendoraCloudAuthError.Unknown(
        t.message ?: "Request timed out",
        code = "NETWORK_TIMEOUT",
        kind = SendoraCloudAuthErrorKind.NETWORK,
    )
    else -> SendoraCloudAuthError.Unknown(
        t.message ?: t.javaClass.simpleName,
        code = "UNKNOWN_ERROR",
        kind = SendoraCloudAuthErrorKind.UNKNOWN,
    )
}

/**
 * Detail handed to onDeviceTakeover subscribers. Fires once per
 * identified-signin call where the backend retired an anonymous
 * user_id (anon → identified flip on the same device, s58.111+).
 * Host app's only job is to delete the matching row from any
 * local mirror table so audience queries joining on user_id stop
 * matching the stale anon row.
 */
data class DeviceTakeoverEvent(
    val retiredAnonUserId: String,
    val identifiedUserId: String,
    val at: Long,
)

/**
 * Detail handed to [SendoraCloudAuth.onDeletionCancelled] subscribers (s58.269).
 * Fires once per sign-in that cancelled a pending self-service account deletion
 * within its grace window — the account is restored with the SAME user_id.
 */
/**
 * What happened to the guest ("anonymous") account this device presented, on a
 * sign-in that produced an identified session (s58.278).
 *
 * The one worth acting on is [PRESERVED]: a guest account was presented, was
 * NOT retired, and is therefore still alive server-side — so offering the
 * player "recover your other account" is a real offer rather than a guess.
 */
enum class AnonRetirementOutcome(val wire: String) {
    /** The guest row was deleted; its id arrives via onDeviceTakeover. */
    RETIRED("retired"),
    /** A guest token WAS sent and the guest was NOT retired — it still exists. */
    PRESERVED("preserved"),
    /** No guest token was sent; nothing to reconcile. */
    NONE("none");

    companion object {
        fun fromWire(raw: String?): AnonRetirementOutcome? =
            entries.firstOrNull { it.wire == raw }
    }
}

data class DeletionCancelledEvent(
    val userId: String,
    val at: Long,
)

/**
 * Why the local session ended (4.12.0). Before this, a session that died in the
 * background emitted NOTHING — an app could not tell a deliberate sign-out apart
 * from an expired refresh token, and only discovered the difference when
 * `getAccessToken()` started returning null.
 *
 * - [USER]            — the app called `signOut()`.
 * - [SESSION_EXPIRED] — the server rejected the stored refresh token (revoked,
 *                       expired, rotated away). Transient network failures and
 *                       rate limits do NOT produce this.
 * - [ACCOUNT_DELETED] — `deleteAccount()` succeeded.
 */
enum class AuthSignedOutReason { USER, SESSION_EXPIRED, ACCOUNT_DELETED }

/**
 * A single auth-state transition (4.12.0). Subscribe with
 * [SendoraCloudAuth.onAuthStateChanged] — one stream covering everything that
 * used to need separate listeners (or had no signal at all).
 */
sealed class AuthStateChange {
    data class SignedIn(val user: SendoraCloudAuthUser) : AuthStateChange()
    data class SignedOut(val reason: AuthSignedOutReason) : AuthStateChange()
    data class DeviceTakeover(
        val user: SendoraCloudAuthUser?,
        val retiredAnonUserId: String,
    ) : AuthStateChange()
    data class DeletionCancelled(val user: SendoraCloudAuthUser?) : AuthStateChange()
}

class SendoraCloudAuth internal constructor(
    private val client: ApiClient,
    private val storage: Storage,
    private val onIdentityChange: (String?) -> Unit,
    private val onAnonymousWipe: suspend () -> Unit,
) {
    @Volatile private var cachedUser: SendoraCloudAuthUser? = null
    @Volatile private var cachedExpiresAt: Long = 0L
    private val mutex = Mutex()
    private val refreshMutex = Mutex()
    // s58.116 — inline device-takeover listeners. UUID-keyed so
    // callers can unsubscribe via the returned lambda.
    private val takeoverListeners = java.util.concurrent.ConcurrentHashMap<java.util.UUID, (DeviceTakeoverEvent) -> Unit>()
    @Volatile private var lastTakeover: DeviceTakeoverEvent? = null
    private val deletionCancelledListeners = java.util.concurrent.ConcurrentHashMap<java.util.UUID, (DeletionCancelledEvent) -> Unit>()
    @Volatile private var lastDeletionCancelled: DeletionCancelledEvent? = null
    @Volatile private var lastAnonRetirement: AnonRetirementOutcome? = null
    // 4.12.0 — single auth-state stream. Same UUID-keyed posture as the two
    // listeners above; those keep firing unchanged alongside it.
    private val authStateListeners = java.util.concurrent.ConcurrentHashMap<java.util.UUID, (AuthStateChange) -> Unit>()
    /**
     * True once the constructor finished restoring (or declining to restore) the
     * cached session. Distinguishes "not restored YET" from "genuinely signed
     * out" for [onAuthStateChanged]'s replay-on-subscribe.
     */
    @Volatile private var hydrated = false
    // Long-lived coroutine scope for the proactive-refresh cron (s58.73).
    // SupervisorJob so a single tick failure doesn't kill the loop.
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val refreshSafetyMs = 30_000L

    init {
        // Re-hydrate session from EncryptedSharedPreferences. Drop the
        // cache if the JSON is malformed or carries an empty id —
        // either signal corruption / a forged write. The REFRESH token
        // survives that drop (see clearCachedUser): it is independently
        // valid and is the only thing that can still recover the account,
        // so a torn write to the user blob must not cost the session.
        storage.authUserJson?.let { json ->
            runCatching {
                val obj = JSONObject(json)
                val id = obj.optString("id")
                if (id.isNotEmpty()) {
                    cachedUser = SendoraCloudAuthUser(
                        id = id,
                        email = obj.opt("email")?.takeIf { it != JSONObject.NULL } as? String,
                        emailVerified = obj.optBoolean("emailVerified", false),
                        name = obj.opt("name")?.takeIf { it != JSONObject.NULL } as? String,
                        isAnonymous = obj.optBoolean("isAnonymous", false),
                        signupMethod = obj.opt("signupMethod")?.takeIf { it != JSONObject.NULL } as? String, // s58.266
                        lastLoginMethod = obj.opt("lastLoginMethod")?.takeIf { it != JSONObject.NULL } as? String,
                    )
                    cachedExpiresAt = storage.authAccessExpiresAt
                    cachedUser?.let { onIdentityChange(it.id) }
                } else {
                    storage.clearCachedUser()
                }
            }.onFailure { storage.clearCachedUser() }
        }
        hydrated = true
    }

    val currentUser: SendoraCloudAuthUser? get() = cachedUser

    /** Synchronous read — returns whatever's cached, even if expired.
     *  Prefer `getAccessToken()` for transparent refresh. */
    val accessToken: String? get() = storage.authAccessToken

    /**
     * Returns a non-expired access token. Triggers a single-flight
     * refresh if the cached token is past expiry.
     *
     * s58.47 — when the cached ACCESS token is missing but a refresh
     * token is still in EncryptedSharedPreferences (cold start after
     * the access token's 15-min TTL elapsed, partial persist, or
     * AndroidKeyStore eviction), drive a refresh instead of
     * returning null. Pre-s58.47 we bailed immediately, which left
     * the host app reading null and triggering a fresh anonymous
     * mint on every cold launch.
     */
    suspend fun getAccessToken(): String? = guardedValue {
        val token = storage.authAccessToken
        val exp = cachedExpiresAt
        val nowMs = System.currentTimeMillis()
        if (token != null && exp > 0 && nowMs < exp - refreshSafetyMs) return@guardedValue token
        // Either no access token at all, or it's past (expiry - safety).
        // refreshAccessToken handles both: it short-circuits when no
        // refresh token is in storage either, returning null.
        refreshAccessToken()
    }

    /**
     * Return the anonymous session this device already holds, or mint one.
     *
     * The reuse short-circuit is the same one Firebase's `signInAnonymously`
     * performs, and it is not an optimisation. Minting unconditionally means an
     * app that calls this defensively on every cold launch — the most natural
     * thing to write — gets a fresh `user_id` each time, and [persist]
     * overwrites the stored refresh token, the previous anonymous account's
     * ONLY durable handle, with no takeover, no webhook and no state event.
     * That is the same silent, permanent progress loss as a failed sign-in
     * wiping the session, except it happens on a *healthy* network.
     *
     * Reuse requires BOTH halves of the session: a cached anonymous user AND a
     * refresh token on disk. The cached user alone is not enough — without the
     * token there is nothing left to authenticate with, so that account is
     * already unreachable and minting is the only way forward.
     *
     * Pass `forceNew = true` to deliberately abandon the current anonymous
     * session and mint a separate one.
     */
    suspend fun signInAnonymously(
        name: String? = null,
        metadata: Map<String, Any>? = null,
        forceNew: Boolean = false,
    ): Result<SendoraCloudAuthUser> = serialize {
        if (!storage.isSecureAvailable) {
            return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable(
                "EncryptedSharedPreferences unavailable — refusing to mint a session that can't be persisted securely"
            ))
        }
        val existing = cachedUser
        if (!forceNew && existing?.isAnonymous == true && storage.authRefreshToken != null) {
            return@serialize Result.success(existing)
        }
        val body = mutableMapOf<String, Any?>()
        name?.let { body["name"] = it }
        metadata?.let { body["metadata"] = it }
        callAuth("/auth-service/anonymous", body)
    }

    suspend fun signUp(
        email: String,
        password: String,
        name: String? = null,
        metadata: Map<String, Any>? = null,
    ): Result<SendoraCloudAuthUser> = serialize {
        if (!storage.isSecureAvailable) {
            return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable(
                "EncryptedSharedPreferences unavailable — refusing to persist auth tokens"
            ))
        }
        val isAnonymous = cachedUser?.isAnonymous == true
        val refresh = storage.authRefreshToken
        if (isAnonymous && refresh != null) {
            val body = mutableMapOf<String, Any?>(
                "refreshToken" to refresh,
                "email" to email,
                "password" to password,
            )
            name?.let { body["name"] = it }
            return@serialize callAuth("/auth-service/upgrade", body)
        }
        // ADR-030 §4: already signed in with an identity. signUp() would orphan
        // the current account by minting a second one — refuse and point at
        // link*() (was: silently wiped + fresh-signup = duplicate account). A
        // genuinely signed-out caller (no cachedUser) still falls through.
        if (cachedUser != null && cachedUser?.isAnonymous == false) {
            return@serialize Result.failure(SendoraCloudAuthError.AlreadyIdentified(
                "Already signed in. Use linkEmailPassword() to add a password to this account, or sign out first."
            ))
        }
        val body = mutableMapOf<String, Any?>("email" to email, "password" to password)
        name?.let { body["name"] = it }
        metadata?.let { body["metadata"] = it }
        callAuth("/auth-service/signup", body)
    }

    suspend fun signIn(email: String, password: String): Result<SendoraCloudAuthUser> = serialize {
        if (!storage.isSecureAvailable) {
            return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable(
                "EncryptedSharedPreferences unavailable — refusing to persist auth tokens"
            ))
        }
        // Device-takeover (backend s58.111): if this device holds an
        // anonymous session, forward its refresh token to /login so
        // the backend revokes the anon session, reassigns this
        // device's push tokens to the identified user, and deletes
        // the anon user row. One device → one user_id on the platform
        // side. Read WITHOUT wiping — the session has to survive a
        // rejected password, a 429 and airplane mode.
        val prevAnonRefreshToken: String? = takeoverHint()

        val body = mutableMapOf<String, Any?>("email" to email, "password" to password)
        if (prevAnonRefreshToken != null) body["prevAnonRefreshToken"] = prevAnonRefreshToken
        val response = client.post("/auth-service/login", body)
        val err = parseError(response)
        if (err != null) return@serialize Result.failure(err)
        val parsed = parseSuccess(response)
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        // The new session is confirmed — only now may the old identity go.
        // Every return above leaves the caller's account reachable.
        if (cachedUser != null) wipeLocalIdentity()
        persist(response!!)
        Result.success(parsed.first)
    }

    /**
     * Login outcome — `Authenticated` for the standard path,
     * `MfaRequired` when the account has MFA enabled. Caller follows
     * up with `challengeMfa()` to mint the actual session.
     */
    sealed class SignInOutcome {
        data class Authenticated(val user: SendoraCloudAuthUser) : SignInOutcome()
        data class MfaRequired(val challengeToken: String, val userId: String) : SignInOutcome()
    }

    /**
     * Like `signIn()` but discriminates the MFA-required path. Use this
     * when supporting MFA on end-users.
     *
     * Carries the same anon device-takeover hint as [signIn] — without it the
     * backend never retires the anon row on this device (two user_ids, duplicate
     * pushes). And the anon identity has to survive the MFA branch too: the
     * response may be a challenge rather than a session, so the wipe waits until
     * [challengeMfa] has actually minted one.
     */
    suspend fun signInWithMfaSupport(email: String, password: String): Result<SignInOutcome> = serialize {
        if (!storage.isSecureAvailable) {
            return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        val prevAnonRefreshToken: String? = takeoverHint()
        val body = mutableMapOf<String, Any?>("email" to email, "password" to password)
        if (prevAnonRefreshToken != null) body["prevAnonRefreshToken"] = prevAnonRefreshToken
        val response = client.post("/auth-service/login", body)
        val err = parseError(response)
        if (err != null) return@serialize Result.failure(err)
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?>
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        if (data["mfaRequired"] == true) {
            val challengeToken = data["mfaChallengeToken"] as? String
                ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Missing mfaChallengeToken"))
            @Suppress("UNCHECKED_CAST")
            val userMap = data["user"] as? Map<String, Any?>
            val userId = (userMap?.get("id") as? String) ?: ""
            // No wipe: nothing has been minted yet. The anon session stays live
            // so `challengeMfa()` can still read the takeover hint off it, and a
            // user who abandons the TOTP prompt keeps their account.
            return@serialize Result.success(SignInOutcome.MfaRequired(challengeToken, userId))
        }
        val parsed = parseSuccess(response)
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        // Direct success (no MFA) — replace the old identity now, not before.
        if (cachedUser != null) wipeLocalIdentity()
        persist(response!!)
        Result.success(SignInOutcome.Authenticated(parsed.first))
    }

    /**
     * Returns the stored anon refresh token iff the local subject is
     * currently anonymous. Used by every identified-session-mint path
     * so the backend can run device-takeover (s58.111 + s58.112).
     * `internal` so cross-file helpers (passkey assertion) can read
     * it without copying the gating logic.
     */
    internal fun takeoverHint(): String? =
        if (cachedUser?.isAnonymous == true) storage.authRefreshToken else null

    // --- Device-takeover listener (s58.116 parity with RN 1.0.5) ---

    /**
     * Register a callback fired when the backend retires an anon
     * `user_id` during a signin on this device. Use it to delete
     * the matching row from any local mirror table — Sendora's own
     * `auth_service_users` + `push_tokens` are already cleaned up
     * server-side. Returns an unsubscribe lambda.
     *
     * Listeners fire on EVERY identified-signin path: signIn /
     * loginSocial / **signInWithPlayGames** / challengeMfa /
     * verifyMagicLink / verifyEmailOtp / passkey authenticate — fired
     * centrally from `persist()` whenever the response carries
     * `retiredAnonUserId`.
     *
     * ⚠ `signInWithPlayGames` is the one that matters most here, and was
     * missing from this list before 4.16.0. When the presented player
     * identity already belongs to another account, the sign-in ADOPTS that
     * account and the anonymous account on this device is retired — its row
     * is DELETED server-side — while the call itself still SUCCEEDS. This
     * listener is the only client-side signal. Pass
     * `onCredentialInUse = CredentialCollisionPolicy.REJECT` if you would
     * rather it not happen.
     *
     * Local-only — survives webhook receiver downtime. For server-pipeline
     * cleanup also subscribe to the `auth.device_takeover` webhook.
     */
    fun onDeviceTakeover(listener: (DeviceTakeoverEvent) -> Unit): () -> Unit {
        val key = java.util.UUID.randomUUID()
        takeoverListeners[key] = listener
        return { takeoverListeners.remove(key) }
    }

    /**
     * Returns the most recent takeover the SDK observed in this
     * session, or null if none. Lets late subscribers pick up the
     * takeover their handler missed.
     */
    fun getLastDeviceTakeover(): DeviceTakeoverEvent? = lastTakeover

    /**
     * Internal — called from every identified-signin path with the
     * `retiredAnonUserId` parsed off the backend response. Snapshot
     * + dispatch outside any mutex so a listener can't deadlock by
     * re-entering the auth surface.
     *
     * Validates UUID shape before firing. The value comes from a
     * response body that a MitM could tamper; a non-UUID value
     * handed to a listener that interpolates it into a path (the
     * documented pattern) becomes a path-injection sink in the host
     * app.
     */
    internal fun fireDeviceTakeover(retiredAnonUserId: String, identifiedUserId: String) {
        if (retiredAnonUserId.isEmpty()) return
        if (!isCanonicalUuid(retiredAnonUserId)) return
        val evt = DeviceTakeoverEvent(
            retiredAnonUserId = retiredAnonUserId,
            identifiedUserId = identifiedUserId,
            at = System.currentTimeMillis(),
        )
        lastTakeover = evt
        for (fn in takeoverListeners.values.toList()) {
            runCatching { fn(evt) }
        }
    }

    /**
     * Subscribe to deletion-cancelled events (s58.269): fires when a sign-in
     * cancelled a pending self-service account deletion within its grace window
     * (the account is restored, same user_id). Surface "your deletion was
     * cancelled" + reconcile local state. Returns an unsubscribe function.
     */
    fun onDeletionCancelled(listener: (DeletionCancelledEvent) -> Unit): () -> Unit {
        val key = java.util.UUID.randomUUID()
        deletionCancelledListeners[key] = listener
        return { deletionCancelledListeners.remove(key) }
    }

    /** The most recent deletion-cancelled event this session, or null. */
    fun getLastDeletionCancelled(): DeletionCancelledEvent? = lastDeletionCancelled

    /**
     * What the last sign-in did with this device's guest account, or null if no
     * sign-in has happened this session (s58.278). See [AnonRetirementOutcome].
     */
    fun getLastAnonRetirement(): AnonRetirementOutcome? = lastAnonRetirement

    internal fun fireDeletionCancelled(identifiedUserId: String) {
        val evt = DeletionCancelledEvent(userId = identifiedUserId, at = System.currentTimeMillis())
        lastDeletionCancelled = evt
        for (fn in deletionCancelledListeners.values.toList()) {
            runCatching { fn(evt) }
        }
    }

    // --- Auth-state stream (4.12.0) ---

    /**
     * Subscribe to every auth-state transition — the single stream that answers
     * "what happened to my session?". Firebase `onAuthStateChanged` / Supabase
     * `onAuthStateChange` parity. Returns an unsubscribe lambda.
     *
     * The reason it exists: a session that dies in the BACKGROUND (the server
     * rejected the stored refresh token) used to emit no signal whatsoever, so
     * an app could not tell it apart from a deliberate sign-out and only noticed
     * when [getAccessToken] began returning null. That transition is now
     * [AuthStateChange.SignedOut] with [AuthSignedOutReason.SESSION_EXPIRED].
     *
     * Replays the CURRENT state on subscribe once the cached session has been
     * restored — a [AuthStateChange.SignedIn] when one was on disk (works
     * offline; restore is disk-only), so a late subscriber never misses the
     * state it started in. Nothing is emitted for a signed-out cold start, and
     * nothing is ever emitted before restore completes: reporting "signed out"
     * there would be a lie.
     *
     * A FAILED sign-in emits nothing — the session is unchanged, so there is no
     * transition to report. [onDeviceTakeover] / [onDeletionCancelled] keep
     * working unchanged alongside this. Listeners are best-effort (a throwing
     * listener is swallowed) and never affect auth state.
     */
    fun onAuthStateChanged(listener: (AuthStateChange) -> Unit): () -> Unit {
        val key = java.util.UUID.randomUUID()
        authStateListeners[key] = listener
        cachedUser?.takeIf { hydrated }?.let { user ->
            runCatching { listener(AuthStateChange.SignedIn(user)) }
        }
        return { authStateListeners.remove(key) }
    }

    /**
     * Fan a state change out to subscribers. Never throws.
     *
     * Dispatched OFF the caller's coroutine because every emission site
     * (`persist`, `wipeLocalIdentity`) runs while `mutex` is held: a listener
     * that calls back into any suspend auth method — `signOut()` from an
     * `onAuthStateChanged` handler is the obvious one — would otherwise wait
     * on a lock its own call stack owns and deadlock permanently. Listeners
     * are best-effort by contract, so losing the caller's ordering guarantee
     * here costs nothing.
     */
    private fun emitAuthState(change: AuthStateChange) {
        val snapshot = authStateListeners.values.toList()
        if (snapshot.isEmpty()) return
        scope.launch {
            for (fn in snapshot) {
                runCatching { fn(change) }
            }
        }
    }

    /**
     * Exchange the MFA challenge token + TOTP/recovery code for a session. A
     * wrong or expired code leaves the anonymous session that started the
     * sign-in intact, so the user can simply retype the code.
     */
    suspend fun challengeMfa(challengeToken: String, code: String): Result<SendoraCloudAuthUser> = serialize {
        val body = mutableMapOf<String, Any>("challengeToken" to challengeToken, "code" to code)
        takeoverHint()?.let { body["prevAnonRefreshToken"] = it }
        callAuth("/auth-service/mfa/challenge", body, replacesIdentity = true)
    }

    // --- Magic link ---

    suspend fun sendMagicLink(email: String): Result<Unit> = guardedResult {
        val response = client.post("/auth-service/magic-link/request", mapOf("email" to email))
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    // --- Social sign-in (8 providers) ---

    /**
     * Verify an IdP-issued credential and mint a Sendora session.
     * Customer's app handles the IdP dance — typically via
     * androidx.credentials Credential Manager (Google) or the
     * provider's SDK (Facebook, etc) or a Custom Tabs flow — then
     * hands the result here.
     *
     * Provider is one of: google, github, apple, microsoft,
     * linkedin, facebook, twitter, discord. Twitter is rejected
     * server-side per OAuth 2.0 verified-email gap.
     *
     * Pass either `code` + `redirectUri` (authorization-code flow)
     * OR `idToken` (Apple-native style; rare on Android).
     */
    suspend fun loginSocial(
        provider: String,
        code: String? = null,
        idToken: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
        appleFirstName: String? = null,
        appleLastName: String? = null,
        // ADR-025 link-in-place opt-in. When anonymous + `link = true`, an
        // anon→social upgrade KEEPS the same user id (sub) — promoted in place
        // (like Firebase linkWithCredential) instead of a device-takeover that
        // mints a new id. No effect off-anon or on a collision.
        link: Boolean = false,
        /**
         * What to do if this social identity (or its verified email) already
         * belongs to an account. **Leave it null** — the default refuses only
         * when a live guest session would be deleted.
         */
        onCredentialInUse: CredentialCollisionPolicy? = null,
    ): Result<SendoraCloudAuthUser> = serialize {
        if (!storage.isSecureAvailable) {
            return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        // Device-takeover hint — same posture as signIn(): read, never wipe.
        // A stale OAuth code, an IdP outage or a dead network must cost the
        // caller nothing.
        val prevAnonRefreshToken: String? = takeoverHint()

        val body = buildMap<String, Any> {
            put("provider", provider)
            code?.let { put("code", it) }
            idToken?.let { put("idToken", it) }
            redirectUri?.let { put("redirectUri", it) }
            codeVerifier?.let { put("codeVerifier", it) }
            if (appleFirstName != null || appleLastName != null) {
                put("appleName", buildMap<String, String> {
                    appleFirstName?.let { put("firstName", it) }
                    appleLastName?.let { put("lastName", it) }
                })
            }
            prevAnonRefreshToken?.let { put("prevAnonRefreshToken", it) }
            // ADR-025: opt into link-in-place (backend ignores it unless anon + new identity).
            if (link) put("linkAnonymous", true)
            // Only sent when explicitly chosen — omitted is the backend's
            // "adopt" default, i.e. exactly what every prior release did.
            onCredentialInUse?.let { put("onCredentialInUse", it.wire) }
        }
        callAuth("/auth-service/login/social", body, replacesIdentity = true)
    }

    suspend fun signInWithGoogle(code: String, redirectUri: String, link: Boolean = false) =
        loginSocial(provider = "google", code = code, redirectUri = redirectUri, link = link)

    /**
     * Google Play Games sign-in (email-less, player-keyed). Pass the
     * serverAuthCode from
     * `PlayGames.getGamesSignInClient(activity).requestServerSideAccess(webClientId, false)`
     * — obtain it via the Play Games SDK (or the Sendora helper). `link = true`
     * KEEPS the same user id when upgrading an anonymous device (ADR-025
     * link-in-place); no effect off-anon or on a collision.
     */
    suspend fun signInWithPlayGames(
        serverAuthCode: String,
        link: Boolean = false,
        /**
         * What to do if this Play Games player identity already belongs to an
         * account. **Leave it null** — the default refuses only when a live
         * guest session would be deleted.
         */
        onCredentialInUse: CredentialCollisionPolicy? = null,
    ): Result<SendoraCloudAuthUser> = serialize {
        if (!storage.isSecureAvailable) {
            return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        // Device-takeover hint — same posture as loginSocial(): read, never wipe.
        // A game signs in on launch over whatever network the device happens to
        // have, and an anonymous player's refresh token is the ONLY handle on
        // their progress — a failed exchange must leave it in place.
        val prevAnonRefreshToken: String? = takeoverHint()

        val body = buildMap<String, Any> {
            put("serverAuthCode", serverAuthCode)
            prevAnonRefreshToken?.let { put("prevAnonRefreshToken", it) }
            // ADR-025: opt into link-in-place (backend ignores it unless anon + new identity).
            if (link) put("linkAnonymous", true)
            // See loginSocial — omitted means the server's "adopt".
            onCredentialInUse?.let { put("onCredentialInUse", it.wire) }
        }
        callAuth("/auth-service/login/play-games", body, replacesIdentity = true)
    }

    suspend fun signInWithGitHub(code: String, redirectUri: String) =
        loginSocial(provider = "github", code = code, redirectUri = redirectUri)

    /** Apple Sign In. Pass `idToken` from the native flow + name fields on first sign-in. `link` = ADR-025 keep-the-sub on an anon upgrade. */
    suspend fun signInWithApple(
        idToken: String,
        firstName: String? = null,
        lastName: String? = null,
        link: Boolean = false,
    ) = loginSocial(
        provider = "apple",
        idToken = idToken,
        appleFirstName = firstName,
        appleLastName = lastName,
        link = link,
    )

    suspend fun signInWithMicrosoft(code: String, redirectUri: String) =
        loginSocial(provider = "microsoft", code = code, redirectUri = redirectUri)

    suspend fun signInWithLinkedIn(code: String, redirectUri: String) =
        loginSocial(provider = "linkedin", code = code, redirectUri = redirectUri)

    suspend fun signInWithFacebook(code: String, redirectUri: String) =
        loginSocial(provider = "facebook", code = code, redirectUri = redirectUri)

    suspend fun signInWithDiscord(code: String, redirectUri: String) =
        loginSocial(provider = "discord", code = code, redirectUri = redirectUri)

    suspend fun verifyMagicLink(token: String): Result<SendoraCloudAuthUser> = serialize {
        if (!storage.isSecureAvailable) {
            return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        // A magic-link token arrives from a tapped email link and is routinely
        // expired or already-consumed (mail scanners pre-fetch links, users tap
        // twice). Those rejections must not cost the session, so nothing local
        // is touched until the verify comes back a success.
        val prev = takeoverHint()
        val body = mutableMapOf<String, Any>("token" to token)
        prev?.let { body["prevAnonRefreshToken"] = it }
        callAuth("/auth-service/magic-link/verify", body, replacesIdentity = true)
    }

    // --- Email OTP (6-digit cross-device code) ---

    suspend fun sendEmailOtp(email: String): Result<Unit> = guardedResult {
        val response = client.post("/auth-service/email-otp/request", mapOf("email" to email))
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    suspend fun verifyEmailOtp(email: String, code: String): Result<SendoraCloudAuthUser> = serialize {
        if (!storage.isSecureAvailable) {
            return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
        }
        // Mistyping a 6-digit code is the single most common outcome of this
        // flow — the user has to be able to retry with their session still
        // there, so the local identity survives until the code verifies.
        val prev = takeoverHint()
        val body = mutableMapOf<String, Any>("email" to email, "code" to code)
        prev?.let { body["prevAnonRefreshToken"] = it }
        callAuth("/auth-service/email-otp/verify", body, replacesIdentity = true)
    }

    // --- Password reset + email verification ---

    /** Trigger a password-reset email. Backend always succeeds even when address is unknown (anti-enumeration). */
    suspend fun requestPasswordReset(email: String): Result<Unit> = guardedResult {
        val response = client.post("/auth-service/password/forgot", mapOf("email" to email))
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    /** Pair the reset-email token with the user's new password. */
    suspend fun resetPassword(token: String, newPassword: String): Result<Unit> = guardedResult {
        val response = client.post(
            "/auth-service/password/reset",
            mapOf("token" to token, "newPassword" to newPassword),
        )
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    /** Verify the email-address token from the link Sendora sent on signup. */
    suspend fun verifyEmail(token: String): Result<Unit> = guardedResult {
        val response = client.post("/auth-service/email/verify", mapOf("token" to token))
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    /** Re-send the email-verification email for the currently-signed-in user. No-op when already verified. */
    suspend fun sendVerificationEmail(): Result<Unit> = guardedResult {
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/email/verify/resend", emptyMap(), headers)
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    // --- MFA enrollment management (Bearer-authenticated) ---

    data class MfaEnrollment(val secret: String, val otpauthUrl: String, val recoveryCodes: List<String>)

    suspend fun enrollMfa(): Result<MfaEnrollment> = guardedResult {
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/mfa/enroll/start", emptyMap(), headers)
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?>
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unknown("Malformed enrollment response"))
        val secret = data["secret"] as? String
        val url = data["otpauthUrl"] as? String
        @Suppress("UNCHECKED_CAST")
        val codes = (data["recoveryCodes"] as? List<String>) ?: emptyList()
        if (secret.isNullOrEmpty() || url.isNullOrEmpty()) {
            return@guardedResult Result.failure(SendoraCloudAuthError.Unknown("Malformed enrollment response"))
        }
        Result.success(MfaEnrollment(secret, url, codes))
    }

    suspend fun confirmMfa(code: String): Result<Boolean> = guardedResult {
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/mfa/enroll/confirm", mapOf("code" to code), headers)
        @Suppress("UNCHECKED_CAST")
        val confirmed = (response?.get("data") as? Map<String, Any?>)?.get("confirmed") as? Boolean ?: false
        Result.success(confirmed)
    }

    suspend fun disableMfa(): Result<Unit> = guardedResult {
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        client.post("/auth-service/mfa/disable", emptyMap(), headers)
        Result.success(Unit)
    }

    // --- Device sessions self-service ---

    data class DeviceSession(
        val id: String,
        val deviceInfo: String?,
        val lastUsedAt: String?,
        val createdAt: String,
    )

    suspend fun listMySessions(): List<DeviceSession> = guardedValue {
        val headers = bearerHeaders() ?: return@guardedValue emptyList()
        val response = client.get("/auth-service/sessions/me", headers)
        @Suppress("UNCHECKED_CAST")
        val arr = response?.get("data") as? List<Map<String, Any?>> ?: return@guardedValue emptyList()
        arr.mapNotNull { row ->
            val id = row["id"] as? String ?: return@mapNotNull null
            val createdAt = row["createdAt"] as? String ?: return@mapNotNull null
            DeviceSession(
                id = id,
                deviceInfo = row["deviceInfo"] as? String,
                lastUsedAt = row["lastUsedAt"] as? String,
                createdAt = createdAt,
            )
        }
    }

    suspend fun revokeSession(sessionId: String) = guardedValue {
        val headers = bearerHeaders() ?: return@guardedValue
        client.delete("/auth-service/sessions/me/$sessionId", headers)
        Unit
    }

    suspend fun revokeAllSessions() = guardedValue {
        val headers = bearerHeaders() ?: return@guardedValue
        client.delete("/auth-service/sessions/me", headers)
        Unit
    }

    /**
     * Outcome of [deleteAccount]. [status] is `"purged"` (hard-deleted now,
     * grace = 0) or `"pending"` (deactivated + sessions revoked now, hard
     * delete scheduled at [scheduledPurgeAt]; cancellable by signing back in).
     */
    data class AccountDeletionResult(
        val status: String,
        val scheduledPurgeAt: String?,
        val graceDays: Int,
    )

    /**
     * Delete the signed-in user's account (Apple App Store Guideline 5.1.1(v)).
     * Honors the project's configured grace period; wipes local identity on
     * success (the server has revoked the session). Fails when no user is
     * signed in or the request errors.
     *
     * Resolves a FRESH access token via [getAccessToken] first (refreshing a
     * past-expiry cached token) — this is a one-shot destructive action, so a
     * 401 from a stale token would silently strand the user with an undeleted
     * account (the cause of the prod 401s when "delete" was tapped after the
     * app sat idle). [getAccessToken] uses a separate `refreshMutex`, so calling
     * it while holding `mutex` here does not deadlock.
     */
    suspend fun deleteAccount(): Result<AccountDeletionResult> = serialize {
        val token = getAccessToken()
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val headers = mapOf("Authorization" to "Bearer $token")
        val res = client.delete("/auth-service/me", headers)
            ?: return@serialize Result.failure(SendoraCloudAuthError.Network("deleteAccount failed (network error)"))
        // Require a CONFIRMED success before wiping. Keying off the presence of
        // an `error` object let a `success: false` body with no error through —
        // the account survives server-side while the device throws away the only
        // credential that could reach it again.
        if (res["success"] as? Boolean != true) {
            val err = objectField(res["error"])
            val msg = err?.get("message") as? String ?: "deleteAccount failed"
            return@serialize Result.failure(SendoraCloudAuthError.Network(msg))
        }
        @Suppress("UNCHECKED_CAST")
        val data = res["data"] as? Map<String, Any?>
        // Account is gone / deactivated server-side — drop local identity.
        wipeLocalIdentity(WipeReason.ACCOUNT_DELETED)
        Result.success(AccountDeletionResult(
            status = data?.get("status") as? String ?: "pending",
            scheduledPurgeAt = data?.get("scheduledPurgeAt") as? String,
            graceDays = (data?.get("graceDays") as? Number)?.toInt() ?: 0,
        ))
    }

    // --- Identity linking (ADR-030) ---
    //
    // Attach a SECOND credential to the CURRENT signed-in account, preserving the
    // same user id (sub). Unlike signUp()/loginSocial(link) — which preserve the
    // sub only from an ANONYMOUS session — these operate on an already-identified
    // account. Bearer-authenticated; NO token rotation (the cached user is
    // refreshed in place). Collision -> [SendoraCloudAuthError.CredentialInUse]
    // (never merges). Primary use: one account across platforms — a Play Games
    // player links email/Google, then signs in on iOS to the SAME sub.

    /** Link email + password to the current account (sub preserved). */
    suspend fun linkEmailPassword(email: String, password: String): Result<SendoraCloudAuthUser> =
        linkCredential("/auth-service/me/link/email", mapOf("email" to email, "password" to password))

    /** Link an OAuth social identity. Pass a native `idToken` OR a web `code` + `redirectUri`. */
    suspend fun linkSocial(
        provider: String,
        idToken: String? = null,
        code: String? = null,
        redirectUri: String? = null,
    ): Result<SendoraCloudAuthUser> {
        val body = mutableMapOf<String, Any?>("provider" to provider)
        idToken?.let { body["idToken"] = it }
        code?.let { body["code"] = it }
        redirectUri?.let { body["redirectUri"] = it }
        return linkCredential("/auth-service/me/link/social", body)
    }

    /** Convenience: link a Google identity (native `idToken`, or web `code`+`redirectUri`). */
    suspend fun linkGoogle(idToken: String? = null, code: String? = null, redirectUri: String? = null): Result<SendoraCloudAuthUser> =
        linkSocial("google", idToken, code, redirectUri)

    /** Convenience: link an Apple identity. */
    suspend fun linkApple(idToken: String? = null, code: String? = null, redirectUri: String? = null): Result<SendoraCloudAuthUser> =
        linkSocial("apple", idToken, code, redirectUri)

    /** Link a Google Play Games identity to the current account. Pass the
     *  `serverAuthCode` from `requestServerSideAccess` (same input as
     *  [signInWithPlayGames]). */
    suspend fun linkPlayGames(serverAuthCode: String): Result<SendoraCloudAuthUser> =
        linkCredential("/auth-service/me/link/play-games", mapOf("serverAuthCode" to serverAuthCode))

    /** One credential linked to an account (ADR-030 read side, s58.270). */
    data class LinkedIdentity(
        val provider: String,
        val email: String?,
        val linkedAt: String,
    )

    /** Result of [listLinkedIdentities] — the full connected-account set. */
    data class LinkedIdentitiesResult(
        val identities: List<LinkedIdentity>,
        val hasPassword: Boolean,
    )

    /**
     * List the auth methods/identities linked to the current account (ADR-030
     * read side, s58.270): every social/gaming identity plus a [hasPassword]
     * flag — the cross-device / reinstall-durable source of truth for a
     * "Connected: Play Games · Google" UI (an on-device tracker misses a link
     * made on another device). Bearer-authenticated network read that resolves a
     * fresh access token first (mirrors [deleteAccount]; [getAccessToken] uses a
     * separate refreshMutex, so calling it while holding `mutex` is safe).
     * Firebase `user.providerData` / Supabase `user.identities` parity.
     */
    suspend fun listLinkedIdentities(): Result<LinkedIdentitiesResult> = serialize {
        val token = getAccessToken()
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unauthorized("Sign in before listing linked identities"))
        val headers = mapOf("Authorization" to "Bearer $token")
        val response = client.get("/auth-service/me/identities", headers)
            ?: return@serialize Result.failure(SendoraCloudAuthError.Network("listLinkedIdentities failed (network error)"))
        val err = parseError(response)
        if (err != null) return@serialize Result.failure(err)
        @Suppress("UNCHECKED_CAST")
        val data = response["data"] as? Map<String, Any?>
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Malformed identities response"))
        @Suppress("UNCHECKED_CAST")
        val rows = data["identities"] as? List<Map<String, Any?>> ?: emptyList()
        val identities = rows.mapNotNull { row ->
            val provider = row["provider"] as? String ?: return@mapNotNull null
            if (provider.isEmpty()) return@mapNotNull null
            val linkedAt = row["linkedAt"] as? String ?: return@mapNotNull null
            LinkedIdentity(provider = provider, email = row["email"] as? String, linkedAt = linkedAt)
        }
        val hasPassword = data["hasPassword"] as? Boolean ?: false
        Result.success(LinkedIdentitiesResult(identities = identities, hasPassword = hasPassword))
    }

    /** Shared link executor. Resolves a fresh access token, POSTs the credential
     *  with the Bearer header, then refreshes the cached user IN PLACE (no token
     *  rotation — the sub is unchanged). Mirrors [deleteAccount]'s Bearer flow;
     *  [getAccessToken] uses a separate refreshMutex, so calling it while holding
     *  `mutex` here does not deadlock. */
    private suspend fun linkCredential(path: String, body: Map<String, Any?>): Result<SendoraCloudAuthUser> = serialize {
        val token = getAccessToken()
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unauthorized("Sign in before linking a credential"))
        val headers = mapOf("Authorization" to "Bearer $token")
        val response = client.post(path, body, headers)
        val err = parseError(response)
        if (err != null) return@serialize Result.failure(err)
        val user = parseLinkedUser(response)
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Malformed link response"))
        // 4.15.0 — linking a provider identity from an ANONYMOUS session
        // promotes this account in place (sub preserved) and the server rotates
        // the session, because the `is_anonymous` JWT claim just changed. The
        // old refresh token is revoked server-side, so installing the returned
        // pair is NOT optional: skip it and this device is signed out at the
        // next refresh. An identified link returns no tokens and keeps the
        // ADR-030 in-place behaviour.
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?>
        // Gate on the tokens ACTUALLY parsing, not just on the flag: `persist`
        // no-ops when `parseSuccess` returns null, so committing to this branch
        // on a malformed response would leave the row still marked anonymous
        // locally, holding tokens the server has already revoked — i.e. signed
        // out at the next refresh. Falling through to `updateLocalUser` keeps
        // the live session instead. (RN/web get this from `isAuthApiResponse`,
        // iOS from the `parseTokens` binding.)
        if (data?.get("upgraded") == true && parseSuccess(response) != null) {
            persist(response!!)
            return@serialize Result.success(user)
        }
        updateLocalUser(user)
        Result.success(user)
    }

    /** Parse the user off a response independently of its tokens, which
     *  [parseSuccess] requires: a link response carries none at all, and a
     *  refresh response's user is adopted separately from the rotated trio. */
    @Suppress("UNCHECKED_CAST")
    private fun parseLinkedUser(response: Map<String, Any?>?): SendoraCloudAuthUser? {
        val data = response?.get("data") as? Map<String, Any?> ?: return null
        val userMap = data["user"] as? Map<String, Any?> ?: return null
        val id = userMap["id"] as? String
        if (id.isNullOrEmpty()) return null
        return SendoraCloudAuthUser(
            id = id,
            email = userMap["email"] as? String,
            emailVerified = userMap["emailVerified"] as? Boolean ?: false,
            name = userMap["name"] as? String,
            isAnonymous = userMap["isAnonymous"] as? Boolean ?: false,
            signupMethod = userMap["signupMethod"] as? String,
            lastLoginMethod = userMap["lastLoginMethod"] as? String,
        )
    }

    /** Refresh the cached user after a link — the sub is unchanged, so only the
     *  user object + its stored copy change (no token/identity rotation). */
    private fun updateLocalUser(user: SendoraCloudAuthUser) {
        cachedUser = user
        storage.authUserJson = JSONObject().apply {
            put("id", user.id)
            put("email", user.email ?: JSONObject.NULL)
            put("emailVerified", user.emailVerified)
            put("name", user.name ?: JSONObject.NULL)
            put("isAnonymous", user.isAnonymous)
            put("signupMethod", user.signupMethod ?: JSONObject.NULL)
            put("lastLoginMethod", user.lastLoginMethod ?: JSONObject.NULL)
        }.toString()
    }

    private fun bearerHeaders(): Map<String, String>? {
        val token = storage.authAccessToken ?: return null
        return mapOf("Authorization" to "Bearer $token")
    }

    suspend fun signOut() = guardedValue {
        mutex.withLock {
            // Wipe FIRST so the user is logged out on device even if the
            // revoke request hangs (airplane mode, 5xx, circuit open).
            // Refresh token still expires server-side. (The one place a
            // pre-call wipe is correct: the caller ASKED to lose the session.)
            val refresh = storage.authRefreshToken
            wipeLocalIdentity(WipeReason.USER)
            if (refresh != null) {
                // Fire-and-forget on a detached scope so the local wipe
                // is the user-visible outcome.
                CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
                    runCatching {
                        client.post("/auth-service/token/revoke", mapOf("refreshToken" to refresh))
                    }
                }
            }
        }
    }

    // --- Internals ---

    /**
     * Coercion boundary for a public auth op that answers with a [Result]:
     * anything thrown inside becomes a typed [SendoraCloudAuthError] failure
     * (see [asAuthError]) instead of escaping raw with no `kind` to branch on.
     *
     * [CancellationException] is rethrown BEFORE the catch-all, and that
     * ordering is load-bearing — reporting a cancelled coroutine as a failure
     * would hide the cancellation from the caller's scope.
     */
    private suspend fun <T> guardedResult(block: suspend () -> Result<T>): Result<T> =
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (t: Throwable) {
            Result.failure(asAuthError(t))
        }

    /**
     * [guardedResult] for an op that answers with a plain value: the failure can
     * only be reported by throwing, so it is thrown typed.
     */
    private suspend fun <T> guardedValue(block: suspend () -> T): T =
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (t: Throwable) {
            throw asAuthError(t)
        }

    /**
     * The single choke point every mutating public auth op passes through: the
     * serialization `mutex` — so a UI double-submit can't mint two anonymous
     * users or interleave a signIn + signOut — plus [guardedResult]'s coercion.
     * Keeping both here is what makes the coercion impossible to forget when a
     * new op is added.
     */
    private suspend fun <T> serialize(block: suspend () -> Result<T>): Result<T> =
        mutex.withLock { guardedResult(block) }

    /**
     * Post an auth request and install the resulting session.
     *
     * [replacesIdentity] marks the paths that switch the device from one subject
     * to another (social / Play Games / magic link / email OTP / MFA challenge):
     * they clear the previous identity — rotating the anon id and dropping the
     * queued events with it — but ONLY here, after the response has validated.
     * The anonymous-mint and in-place upgrade paths pass false: they keep the
     * same subject, so rotating device state under them would orphan attribution
     * that legitimately belongs to the user.
     */
    private suspend fun callAuth(
        path: String,
        body: Map<String, Any?>,
        replacesIdentity: Boolean = false,
    ): Result<SendoraCloudAuthUser> {
        val response = client.post(path, body)
        val err = parseError(response)
        if (err != null) return Result.failure(err)
        val parsed = parseSuccess(response)
            ?: return Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        if (replacesIdentity && cachedUser != null) wipeLocalIdentity()
        persist(response!!)
        return Result.success(parsed.first)
    }

    /**
     * Hot-path token refresh. Mutexed so a coroutine fan-out doesn't
     * produce duplicate /refresh round-trips.
     *
     * s58.46 — on a dead-token signal (INVALID_REFRESH_TOKEN /
     * UNAUTHORIZED / HTTP_401) we WIPE the stored refresh token.
     * Pre-s58.46 we returned null but kept the dead token in storage,
     * so the next caller re-tried the same token forever (Pulse News
     * iOS hit /refresh ~1×/s for hours). The wipe forces the next op
     * to fall through to anonymous mint or surface signed-out state
     * to the host app instead of looping. It is the ONE background
     * wipe in the SDK, and it emits
     * [AuthSignedOutReason.SESSION_EXPIRED] so the app hears about a
     * session that died while it wasn't looking.
     */
    private suspend fun refreshAccessToken(): String? = refreshMutex.withLock {
        val nowMs = System.currentTimeMillis()
        // Re-check after acquiring the lock; another caller may have
        // already refreshed.
        val exp = cachedExpiresAt
        val cached = storage.authAccessToken
        if (cached != null && exp > 0 && nowMs < exp - refreshSafetyMs) return@withLock cached

        val refresh = storage.authRefreshToken ?: return@withLock null
        val response = client.post("/auth-service/token/refresh", mapOf("refreshToken" to refresh))
        if (response != null && response["success"] == false) {
            val error = objectField(response["error"])
            val code = error?.get("code") as? String
            // Only wipe if the token the server rejected is STILL the stored
            // one. A sign-in or signOut that landed while this request was in
            // flight already replaced it, and that newer session is not the
            // one the server declared dead.
            if (code != null && isDeadRefreshError(code) && tokenStillCurrent(refresh)) {
                wipeLocalIdentity(WipeReason.SESSION_EXPIRED)
            }
            return@withLock null
        }
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?> ?: return@withLock null
        // The rotated trio lives under `data.tokens` (alongside `data.user`),
        // matching every other auth response. It was FLAT before s58.76, and
        // reading the wrong level does not fail loudly — it just never
        // refreshes, so the session dies at access-token expiry and the app
        // mints a fresh anonymous user, silently fragmenting the account.
        // Accept both levels.
        @Suppress("UNCHECKED_CAST")
        val tokenFields = (data["tokens"] as? Map<String, Any?>) ?: data
        val accessToken = tokenFields["accessToken"] as? String
        val refreshToken = tokenFields["refreshToken"] as? String
        val expiresIn = (tokenFields["expiresIn"] as? Number)?.toLong()
        if (accessToken.isNullOrEmpty() || refreshToken.isNullOrEmpty() || expiresIn == null || expiresIn <= 0) {
            return@withLock null
        }
        // Installing this would resurrect a session the user just signed out
        // of, or clobber a newer one. The revoke signOut fires cannot save us:
        // it hashes the PRE-rotation token, while a successful refresh has
        // already minted a new server-side session row.
        if (!tokenStillCurrent(refresh)) return@withLock null
        val newExp = nowMs + expiresIn * 1000L
        storage.authAccessToken = accessToken
        storage.authRefreshToken = refreshToken
        storage.authAccessExpiresAt = newExp
        cachedExpiresAt = newExp
        // Adopt the user the backend returns when we don't have one. Without
        // this the corrupt-cache path is a dead end: the constructor
        // deliberately KEEPS the refresh token when the cached user blob is
        // unreadable (it is the only thing that can still recover the account),
        // but nothing could ever turn that token back into an identity — so the
        // session stayed live with a permanently null user and the next sign-in
        // orphaned it anyway. Only fills a GAP; never overwrites a live user,
        // since a refresh is a token rotation, not an identity change. The
        // route tolerates a missing user row, so `data.user` may be null —
        // [parseLinkedUser] adopts only a well-formed one (non-empty id).
        if (cachedUser == null) {
            parseLinkedUser(response)?.let { recovered ->
                updateLocalUser(recovered)
                onIdentityChange(recovered.id)
                emitAuthState(AuthStateChange.SignedIn(recovered))
            }
        }
        accessToken
    }

    /**
     * Canonical UUID validator. Defends against tampered
     * `retiredAnonUserId` response values reaching host-app
     * listeners as a path-injection sink.
     */
    private fun isCanonicalUuid(s: String): Boolean {
        return try {
            java.util.UUID.fromString(s).toString().equals(s, ignoreCase = true)
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    /**
     * Codes on /token/refresh that mean the stored refresh token is PERMANENTLY
     * dead — the only case where the SDK may wipe local identity in the
     * background. INVALID_REFRESH_TOKEN is the s58.46 canonical code; HTTP_401 /
     * UNAUTHORIZED cover older backend builds that still emit the generic
     * unauthorized shape.
     *
     * RATE_LIMIT / RATE_LIMIT_EXCEEDED are deliberately NOT here. A 429 is
     * transient throttling (a shared NAT/CGN egress ip, a refresh burst) and
     * says nothing about the token's validity — treating it as permanent meant a
     * passing rate limit silently destroyed a live session, including an
     * anonymous one whose refresh token is its only durable handle. Rate limits
     * fall through to the transient path: keep the session, retry later.
     */
    /**
     * ONLY the specific code. `UNAUTHORIZED` / `HTTP_401` used to be accepted
     * here as a catch-all for older backends, but a 401 on this route is NOT
     * proof the refresh token is dead: the API-key middleware returns the same
     * generic 401 for a rotated or expired publishable key. Rotating a `pk_`
     * key would therefore have wiped the stored refresh token of every install
     * at once. Failing to recognise a genuinely dead token only costs a retry
     * loop the backoff already bounds; wiping a live one is irreversible.
     */
    /**
     * True when [sent] is still the refresh token in storage — i.e. nothing
     * replaced or cleared the session while a request carrying it was in
     * flight. Guards both directions of the refresh race: installing a rotated
     * token over a session that has since been signed out or replaced, and
     * wiping a fresh session because an OLD token was rejected.
     */
    private fun tokenStillCurrent(sent: String): Boolean = storage.authRefreshToken == sent

    private fun isDeadRefreshError(code: String): Boolean {
        return code == "INVALID_REFRESH_TOKEN"
    }

    /**
     * Read a nested object off a response envelope. `ApiClient` parses only the
     * TOP level into a Map — its values are still `org.json` objects — so accept
     * either shape rather than silently missing the error/details block.
     */
    private fun objectField(value: Any?): Map<String, Any?>? = when (value) {
        is Map<*, *> -> {
            @Suppress("UNCHECKED_CAST")
            (value as Map<String, Any?>)
        }
        is JSONObject -> value.keys().asSequence().associateWith { key ->
            value.opt(key)?.takeIf { it != JSONObject.NULL }
        }
        else -> null
    }

    /**
     * Pull the `retryAfterSeconds` backoff hint the backend puts in
     * `error.details` (rate limits, account lockout). Absent for every other
     * failure — the app should not invent one.
     */
    private fun readRetryAfterSeconds(error: Map<String, Any?>?): Int? {
        val seconds = (objectField(error?.get("details"))?.get("retryAfterSeconds") as? Number)?.toInt()
        return seconds?.takeIf { it > 0 }
    }

    private fun parseError(response: Map<String, Any?>?): SendoraCloudAuthError? {
        if (response == null) return SendoraCloudAuthError.Network("Network request failed")
        val success = response["success"] as? Boolean ?: false
        if (success) return null
        val error = objectField(response["error"])
        val code = error?.get("code") as? String ?: ""
        val message = error?.get("message") as? String ?: "Auth request failed"
        // HTTP status stamped onto the error envelope by ApiClient — lets a
        // response the backend gave no `code` for still classify (5xx→SERVER,
        // 429→RATE_LIMITED) instead of collapsing to UNKNOWN.
        val status = (error?.get("status") as? Number)?.toInt()
        return when (code) {
            "NOT_ANONYMOUS" -> SendoraCloudAuthError.AlreadyIdentified(message, code, status)
            "CREDENTIAL_IN_USE" -> SendoraCloudAuthError.CredentialInUse(message, code, status)
            "CONFLICT", "EMAIL_ALREADY_TAKEN" -> SendoraCloudAuthError.EmailAlreadyTaken(message, code, status)
            "UNAUTHORIZED" -> SendoraCloudAuthError.Unauthorized(message, code, status)
            // Message format kept verbatim — apps string-match it.
            else -> SendoraCloudAuthError.Unknown(
                "$code: $message",
                code = code.ifEmpty { null },
                status = status,
                retryAfterSeconds = readRetryAfterSeconds(error),
            )
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseSuccess(response: Map<String, Any?>?): Pair<SendoraCloudAuthUser, Map<String, Any?>>? {
        val data = response?.get("data") as? Map<String, Any?> ?: return null
        val userMap = data["user"] as? Map<String, Any?> ?: return null
        val tokensMap = data["tokens"] as? Map<String, Any?> ?: return null
        val id = userMap["id"] as? String
        if (id.isNullOrEmpty()) return null
        val accessToken = tokensMap["accessToken"] as? String
        val refreshToken = tokensMap["refreshToken"] as? String
        val expiresIn = (tokensMap["expiresIn"] as? Number)?.toLong() ?: 0L
        if (accessToken.isNullOrEmpty() || refreshToken.isNullOrEmpty() || expiresIn <= 0) return null
        val user = SendoraCloudAuthUser(
            id = id,
            email = userMap["email"] as? String,
            emailVerified = userMap["emailVerified"] as? Boolean ?: false,
            name = userMap["name"] as? String,
            isAnonymous = userMap["isAnonymous"] as? Boolean ?: false,
            signupMethod = userMap["signupMethod"] as? String,   // s58.266
            lastLoginMethod = userMap["lastLoginMethod"] as? String,
        )
        return user to tokensMap
    }

    internal val passkeys: SendoraCloudPasskeys by lazy {
        SendoraCloudPasskeys(
            client = client,
            storage = storage,
            installSession = { payload ->
                mutex.withLock {
                    val response = mapOf("data" to payload)
                    // Validate the minted session BEFORE dropping the old one —
                    // the assertion round-trip can still come back unusable, and
                    // a wipe on that path would strand the account.
                    if (!storage.isSecureAvailable || parseSuccess(response) == null) null
                    else {
                        if (cachedUser != null) wipeLocalIdentity()
                        persist(response)
                        cachedUser
                    }
                }
            },
            takeoverHintProvider = { takeoverHint() },
        )
    }

    private fun persist(response: Map<String, Any?>) {
        val (user, tokens) = parseSuccess(response) ?: return
        val accessToken = tokens["accessToken"] as String
        val refreshToken = tokens["refreshToken"] as String
        val expiresIn = (tokens["expiresIn"] as Number).toLong()
        val expMs = System.currentTimeMillis() + expiresIn * 1000L

        cachedUser = user
        cachedExpiresAt = expMs
        storage.authAccessToken = accessToken
        storage.authRefreshToken = refreshToken
        storage.authAccessExpiresAt = expMs
        val userJson = JSONObject().apply {
            put("id", user.id)
            put("email", user.email ?: JSONObject.NULL)
            put("emailVerified", user.emailVerified)
            put("name", user.name ?: JSONObject.NULL)
            put("isAnonymous", user.isAnonymous)
            put("signupMethod", user.signupMethod ?: JSONObject.NULL) // s58.266
            put("lastLoginMethod", user.lastLoginMethod ?: JSONObject.NULL)
        }.toString()
        storage.authUserJson = userJson
        onIdentityChange(user.id)
        startProactiveRefreshCron()
        emitAuthState(AuthStateChange.SignedIn(user))

        // s58.116 — fire inline device-takeover listener when the
        // backend retired an anon row during this signin. Read from
        // the outer `data` envelope; passkey path passes `data` only
        // (mapOf("data" to payload)) so this still finds it.
        @Suppress("UNCHECKED_CAST")
        val data = response["data"] as? Map<String, Any?>
        val retiredAnonUserId = data?.get("retiredAnonUserId") as? String
        if (!retiredAnonUserId.isNullOrEmpty()) {
            fireDeviceTakeover(retiredAnonUserId, user.id)
            emitAuthState(AuthStateChange.DeviceTakeover(user, retiredAnonUserId))
        }
        // s58.278 — record the guest-account outcome. Only when the server
        // states it; an older backend leaves the previous value untouched
        // rather than asserting "nothing was retired".
        AnonRetirementOutcome.fromWire(data?.get("anonRetirement") as? String)
            ?.let { lastAnonRetirement = it }
        // s58.269 — fire onDeletionCancelled when this sign-in cancelled a
        // pending self-deletion within grace (account restored, same user_id).
        if (data?.get("reactivatedFromDeletion") as? Boolean == true) {
            fireDeletionCancelled(user.id)
            emitAuthState(AuthStateChange.DeletionCancelled(user))
        }
    }

    /**
     * Why [wipeLocalIdentity] is running. [REPLACED] marks the internal clear
     * that immediately precedes a successful `persist()` — it emits no
     * `SignedOut`, since a subscriber should see one `SignedIn` for a sign-in,
     * not a spurious logout/login pair. Every other value is a real sign-out and
     * is reported as one.
     */
    private enum class WipeReason { REPLACED, USER, SESSION_EXPIRED, ACCOUNT_DELETED }

    /**
     * Drop the local session.
     *
     * ⚠ Never call this ahead of a fallible network request. A failed auth
     * attempt must leave the caller exactly as it found them; for an anonymous
     * session the refresh token dropped here is the ONLY durable handle on the
     * account, so a pre-call wipe that isn't followed by a successful `persist()`
     * orphans it permanently (offline: deterministically). Read the anon refresh
     * into a local, make the call, and wipe only once the response validates.
     */
    private suspend fun wipeLocalIdentity(reason: WipeReason = WipeReason.REPLACED) {
        cachedUser = null
        cachedExpiresAt = 0L
        storage.clearAuthTokens()
        stopProactiveRefreshCron()
        onAnonymousWipe()
        when (reason) {
            WipeReason.REPLACED -> Unit
            WipeReason.USER -> emitAuthState(AuthStateChange.SignedOut(AuthSignedOutReason.USER))
            WipeReason.SESSION_EXPIRED -> emitAuthState(AuthStateChange.SignedOut(AuthSignedOutReason.SESSION_EXPIRED))
            WipeReason.ACCOUNT_DELETED -> emitAuthState(AuthStateChange.SignedOut(AuthSignedOutReason.ACCOUNT_DELETED))
        }
    }

    // ---- Proactive refresh (s58.73) -----------------------------------
    //
    // Background coroutine that ticks every 60s + once on app foreground.
    // Refreshes when access-token TTL has burned ~80% (with ±30s jitter
    // to avoid herd synchronisation across multiple app instances on the
    // same network). Refresh becomes a scheduled event; no more 401-driven
    // race on the next interaction.
    //
    // Foreground signal: ProcessLifecycleOwner.ON_START. We import lazily
    // via reflection because androidx.lifecycle is a host-app dep on the
    // SDK side (no hard dep, lets app authors who don't want lifecycle
    // continue compiling). When unavailable we still get the 60s tick.

    private var proactiveJob: Job? = null
    private var lifecycleObserver: Any? = null

    private fun startProactiveRefreshCron() {
        if (proactiveJob?.isActive == true) return
        proactiveJob = scope.launch {
            while (isActive) {
                tickProactive()
                delay(60_000L)
            }
        }
        registerLifecycleObserver()
    }

    private fun stopProactiveRefreshCron() {
        proactiveJob?.cancel()
        proactiveJob = null
        unregisterLifecycleObserver()
    }

    private suspend fun tickProactive() {
        val nowMs = System.currentTimeMillis()
        val expMs = storage.authAccessExpiresAt
        if (expMs <= 0L) return
        val remainingMs = expMs - nowMs
        if (remainingMs <= 0L) return
        val guessOriginalMs = maxOf(remainingMs, 5L * 60_000L)
        val jitter = Random.nextLong(-30_000L, 30_000L)
        val fireWhenRemainingMs = (guessOriginalMs * 0.2).toLong() + jitter
        if (remainingMs <= fireWhenRemainingMs) {
            refreshAccessToken()
        }
    }

    private fun registerLifecycleObserver() {
        try {
            // Reflection-loaded so the SDK doesn't hard-require
            // androidx.lifecycle. Available on every modern Android app
            // that uses Jetpack, but absent in minimal setups.
            val ownerClass = Class.forName("androidx.lifecycle.ProcessLifecycleOwner")
            val owner = ownerClass.getMethod("get").invoke(null)
            val lifecycle = owner.javaClass.getMethod("getLifecycle").invoke(owner)
            val observerClass = Class.forName("androidx.lifecycle.DefaultLifecycleObserver")
            val handler = java.lang.reflect.Proxy.newProxyInstance(
                observerClass.classLoader,
                arrayOf(observerClass),
            ) { _, method, _ ->
                if (method.name == "onStart") {
                    scope.launch { tickProactive() }
                }
                null
            }
            lifecycle.javaClass.getMethod("addObserver", Class.forName("androidx.lifecycle.LifecycleObserver"))
                .invoke(lifecycle, handler)
            lifecycleObserver = handler
        } catch (_: Throwable) {
            // androidx.lifecycle missing — fall back to the 60s tick only.
        }
    }

    private fun unregisterLifecycleObserver() {
        try {
            val obs = lifecycleObserver ?: return
            val ownerClass = Class.forName("androidx.lifecycle.ProcessLifecycleOwner")
            val owner = ownerClass.getMethod("get").invoke(null)
            val lifecycle = owner.javaClass.getMethod("getLifecycle").invoke(owner)
            lifecycle.javaClass.getMethod("removeObserver", Class.forName("androidx.lifecycle.LifecycleObserver"))
                .invoke(lifecycle, obs)
        } catch (_: Throwable) {
            // No-op — observer was never registered.
        } finally {
            lifecycleObserver = null
        }
    }
}
