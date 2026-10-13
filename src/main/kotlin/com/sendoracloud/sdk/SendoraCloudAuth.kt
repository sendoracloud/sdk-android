package com.sendoracloud.sdk

import com.sendoracloud.sdk.internal.AuthCodecs
import com.sendoracloud.sdk.internal.AuthKeys
import com.sendoracloud.sdk.internal.AuthMachineSets
import com.sendoracloud.sdk.internal.AuthRecord
import com.sendoracloud.sdk.internal.AuthStore
import com.sendoracloud.sdk.internal.AuthTransport
import com.sendoracloud.sdk.internal.HeldGuest
import com.sendoracloud.sdk.internal.HeldSlot
import com.sendoracloud.sdk.internal.ProjectVerdict
import com.sendoracloud.sdk.internal.RefreshCron
import com.sendoracloud.sdk.internal.SendoraCloudLogger
import com.sendoracloud.sdk.internal.decodeJwtPayload
import com.sendoracloud.sdk.internal.projectVerdict
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.net.URLEncoder
import java.security.SecureRandom
import kotlin.random.Random

/**
 * Auth Service surface for the Android SDK — ADR-033 wave 1 (4.26.0): "One
 * Slot, Two Verbs".
 *
 *   - **Sign-in never carries the guest.** A credentialed sign-in from a guest
 *     device HOLDS the guest in a fixed on-device slot and switches; the server
 *     row survives. No request body ever carries `prevAnonRefreshToken`,
 *     `linkAnonymous` or `onCredentialInUse` (INV-3).
 *   - **Link is the only upgrade.** `signUp()`, `loginSocial(link = true)`,
 *     `signInWithPlayGames(link = true)`, `link*()` and the typed `link()` all
 *     go to `/me/link/…` on the current Bearer session — same `sub`; a collision
 *     is a typed result with nothing mutated; over an IDENTIFIED session they
 *     attach or error, never switch (INV-14).
 *   - **One slot, one writer.** `commit()` is the ONLY code that assigns the
 *     user / tokens, writes the frozen keys + `auth_session`, arms the refresh
 *     cron, decides the emitted event and tells the parent SDK the wipe reason
 *     (INV-1). Every public method is sugar for one row of the shared table
 *     (`packages/shared/src/auth-machine/transitions.ts`), replayed by
 *     `AuthMachineConformanceTest`.
 *   - **Proposal, then CAS.** A network call changes nothing until it succeeds,
 *     and its result is applied only if the session it was derived from is
 *     still current — the `sid` family for identity commits, the refresh token
 *     that was SENT for token commits (INV-2).
 *
 * All mutating public ops are serialized through a single Mutex so a UI
 * double-submit can't mint two anonymous users or interleave a signIn +
 * signOut. Tokens persist in `EncryptedSharedPreferences` only; when secure
 * storage is unavailable persistence FAILS instead of falling back to
 * plaintext.
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
    /**
     * ADR-033 B17 (4.26.0) — the account's project pool, the same value as the
     * JWT `project` claim: a project UUID, or `null` for the ORG-WIDE pool
     * (SSO/SCIM accounts). ⚠ `null` is only meaningful when [projectKnown] is
     * true — a backend older than B17 never sends the field, and absent is not
     * the same answer as org-wide.
     */
    val project: String? = null,
    val projectKnown: Boolean = false,
)

/**
 * What a `link = true` sign-in should do when the credential you present already
 * belongs to ANOTHER account (4.15.0; re-based on ADR-033 in 4.26.0).
 *
 * Since 4.26.0 a collision exists only on the LINK path, and nothing is ever
 * destroyed by resolving it: [ADOPT] falls through to a plain switch into the
 * owning account — from a guest the guest is HELD on this device (see
 * [SendoraCloudAuth.heldGuests]); from an identified account nothing is held.
 * [REJECT], or null, fails with [SendoraCloudAuthError.CredentialInUse] so the
 * app can ask the player (the typed [LinkResult.CredentialInUse] from
 * [SendoraCloudAuth.link] is the richer form).
 *
 * ⚠ The field is never sent on the wire any more (INV-3) — it is a client
 * routing choice.
 */
enum class CredentialCollisionPolicy(val wire: String) {
    ADOPT("adopt"),
    REJECT("reject"),
}

/**
 * Closed set of auth failure categories (4.12.0). Branch on
 * [SendoraCloudAuthError.kind] instead of matching the ~20 raw codes the
 * backend and the transport between them can produce.
 *
 * ADR-033's two project-guard refusals (`SESSION_WITHHELD`, `PROJECT_MISMATCH`)
 * reuse [CONFIG] — this set is deliberately NOT widened (every SDK switches on
 * it); read [SendoraCloudAuthError.code] for the specific one.
 */
enum class SendoraCloudAuthErrorKind {
    NETWORK,
    SERVER,
    RATE_LIMITED,
    INVALID_CREDENTIAL,
    ACCOUNT_LOCKED,
    CREDENTIAL_IN_USE,

    /**
     * Refusing to unlink the ONLY way into this account (409). The account
     * would still exist and still hold the user's data with nothing able to
     * authenticate into it — permanent lockout. Add another credential first.
     */
    LAST_CREDENTIAL,
    /**
     * The credential is VALID; the authentication behind it is too old to
     * authorise a credential change (403 `RECENT_AUTH_REQUIRED`). NOT a bad
     * credential — re-run a sign-in the user already has and retry the SAME
     * call. `details.maxAgeSeconds` is the freshness window.
     */
    RECENT_AUTH_REQUIRED,
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
                "LAST_CREDENTIAL" -> return LAST_CREDENTIAL
                // ⚠ A CODE arm, not a status one. The status block below maps
                // any >= 400 to INVALID_CREDENTIAL ("needs new input"), which is
                // the opposite of what a step-up refusal means.
                "RECENT_AUTH_REQUIRED" -> return RECENT_AUTH_REQUIRED
                "NOT_ANONYMOUS", "FORBIDDEN_NON_ANONYMOUS" -> return ALREADY_IDENTIFIED
                "PASSKEY_USER_CANCELLED", "GAME_CENTER_CANCELLED",
                "PLAY_GAMES_CANCELLED", "SSO_CANCELLED" -> return CANCELLED
                "GAME_CENTER_UNAVAILABLE", "PLAY_GAMES_UNAVAILABLE",
                "ENTITLEMENT_ERROR", "tier_required",
                // ADR-033 project guard + held-guest preconditions — client-side,
                // not retryable, the app must act (discard / restore / re-init).
                "SESSION_WITHHELD", "PROJECT_MISMATCH", "HELD_GUEST_LIMIT",
                "HELD_GUEST_PROJECT_MISMATCH", "AMBIGUOUS_HELD_GUEST" -> return CONFIG
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
    /** A credential passed to `link*()` / a `link = true` sign-in is already
     *  attached to a DIFFERENT account (ADR-030 §2). Sendora never auto-merges
     *  two real accounts. `provider` / `collision` carry the B14 payload when
     *  the server sent one (4.26.0, additive). */
    class CredentialInUse(
        message: String,
        code: String? = null,
        status: Int? = null,
        val provider: String? = null,
        val collision: LinkCollision? = null,
    ) : SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CREDENTIAL_IN_USE, code, status)
    class Unauthorized(message: String, code: String? = null, status: Int? = null) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.INVALID_CREDENTIAL, code, status)
    class Network(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.NETWORK, "NETWORK_ERROR")
    class SecureStorageUnavailable(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CONFIG, "SECURE_STORAGE_UNAVAILABLE")

    // ── ADR-033 wave 1 (4.26.0) — all CONFIG unless noted; none retryable ──

    /**
     * The SDK is [AuthStatus.WITHHELD]: a stored session's JWT `project` claim
     * disagrees with `expectedProjectId`, and the verb you called is one of
     * those refused there. Nothing was sent, nothing was written. Exit via
     * [SendoraCloudAuth.discardWithheld] or relaunch with the matching key.
     */
    class SessionWithheld(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CONFIG, "SESSION_WITHHELD")
    /**
     * A session minted by THIS process (mint / sign-in / upgrade response)
     * carries the wrong `project` claim — a wrong-key build. Nothing was
     * installed; the minted refresh token was revoked; `status()` is unchanged.
     */
    class ProjectMismatch(message: String, val expectedProjectId: String, val actualProjectId: String?) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CONFIG, "PROJECT_MISMATCH")
    /**
     * Every held slot is full (K = 5) and the verb would need a free one
     * (`forceNew` at the cap), or no held guest is eligible for auto-restore
     * (all held when an account was deleted / project-withheld). Nothing
     * mutated: [SendoraCloudAuth.restoreHeldGuest] or
     * [SendoraCloudAuth.discardHeldGuest] one of them.
     */
    class HeldGuestLimit(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CONFIG, "HELD_GUEST_LIMIT")
    /** The held guest's `project` (recorded at hold) is not this build's project. Slot kept; no network. */
    class HeldGuestProjectMismatch(message: String, val slotProject: String?, val expectedProjectId: String?) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CONFIG, "HELD_GUEST_PROJECT_MISMATCH")
    /** Two or more guests are held and the verb was called without an `id`. Nothing mutated. */
    class AmbiguousHeldGuest(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CONFIG, "AMBIGUOUS_HELD_GUEST")
    /** The held guest was presented and the server reported it gone (`endReason` deleted|revoked|expired). Slot released. */
    class HeldGuestGone(message: String, val endReason: String?) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.INVALID_CREDENTIAL, "held_guest_gone")
    /**
     * The held guest's token was refused with a verdict that does NOT prove the
     * guest is gone (`reuse`, or no `endReason` at all — an older backend). The
     * slot is KEPT; retry later (the 60 s rotation grace may clear a reuse).
     */
    class RestoreFailed(message: String, val endReason: String?) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.SERVER, "restore_failed")
    /** `switchAccount()` re-fetched a credential that is not the one the player confirmed. Nothing mutated. */
    class CredentialChanged(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.INVALID_CREDENTIAL, "credential_changed")
    /** The result landed after the session it was derived from changed (INV-2 CAS); it was dropped and its tokens revoked. */
    class Superseded(message: String) :
        SendoraCloudAuthError(message, SendoraCloudAuthErrorKind.CANCELLED, "SUPERSEDED")

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
 * Detail handed to onDeviceTakeover subscribers. LEGACY after ADR-033: fires
 * only when the SERVER reports a retirement, which this SDK never requests
 * (no sign-in body carries a guest credential). Kept so installed listeners
 * compile and never fire for 4.26.0 sign-ins.
 */
data class DeviceTakeoverEvent(
    val retiredAnonUserId: String,
    val identifiedUserId: String,
    val at: Long,
)

/**
 * What happened to the guest ("anonymous") account this device presented, on a
 * sign-in that produced an identified session (s58.278). LEGACY after ADR-033:
 * a 4.26.0 sign-in never presents the guest, so the server always answers
 * [NONE]; the device-local answer is [SendoraCloudAuth.heldGuests].
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

/**
 * Detail handed to [SendoraCloudAuth.onDeletionCancelled] subscribers (s58.269).
 * Fires once per sign-in that cancelled a pending self-service account deletion
 * within its grace window — the account is restored with the SAME user_id.
 */
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
 * - [USER]            — the app called `signOut()` (or `discardWithheld()`).
 * - [SESSION_EXPIRED] — the server rejected the stored refresh token. EVERY
 *                       dead verdict, whatever the server's detail: read
 *                       [AuthStateChange.SignedOut.endReason] (`revoked` /
 *                       `deleted` / `expired` / `reuse` / `unknown`) for that.
 *                       Transient network failures and rate limits do NOT
 *                       produce this.
 * - [ACCOUNT_DELETED] — `deleteAccount()` succeeded.
 * - [REVOKED] / [EVICTED] / [DELETED] — ⚠ emitted by 4.26.0 ONLY, never since
 *   4.26.1. 4.26.0 put the server's `endReason` here, which renamed "account
 *   deleted elsewhere" / "sessions revoked" (both SESSION_EXPIRED through
 *   4.25.0) and silently broke listeners matching SESSION_EXPIRED. Kept so code
 *   written against 4.26.0 still compiles. ⚠ Branch with an `else`.
 */
enum class AuthSignedOutReason(val wire: String) {
    USER("user"),
    SESSION_EXPIRED("session_expired"),
    ACCOUNT_DELETED("account_deleted"),
    REVOKED("revoked"),
    EVICTED("evicted"),
    DELETED("deleted"),
}

/**
 * A single auth-state transition (4.12.0; widened in 4.26.0 — ADR-033 INV-7
 * "events are confirmed transitions"). Subscribe with
 * [SendoraCloudAuth.onAuthStateChanged] — one stream covering everything.
 * [event] is the shared snake_case wire name. ⚠ `when` over this type MUST
 * have an `else` branch; members are added additively.
 */
sealed class AuthStateChange {
    abstract val event: String

    /** A session was established or replaced. `cause` is `null` only on the replay to a new subscriber. */
    data class SignedIn(val user: SendoraCloudAuthUser, val cause: AuthSignedInCause? = null) : AuthStateChange() {
        override val event: String get() = "signed_in"
    }
    /** `endReason` (4.26.1) = the server's own verdict on a dead refresh token (B11 wire value); `null` on USER / ACCOUNT_DELETED and from an older backend. */
    data class SignedOut(val reason: AuthSignedOutReason, val endReason: String? = null) : AuthStateChange() {
        override val event: String get() = "signed_out"
    }
    /** LEGACY — fires only when the server reports a retirement, which this SDK never requests. */
    data class DeviceTakeover(
        val user: SendoraCloudAuthUser?,
        val retiredAnonUserId: String,
    ) : AuthStateChange() {
        override val event: String get() = "device_takeover"
    }
    data class DeletionCancelled(val user: SendoraCloudAuthUser?) : AuthStateChange() {
        override val event: String get() = "deletion_cancelled"
    }
    /** The settled boot state, exactly once per subscriber — INCLUDING `SIGNED_OUT`, `UNKNOWN` and `WITHHELD`. */
    data class Initial(val status: AuthStatus, val user: SendoraCloudAuthUser?, val withheld: WithheldInfo? = null) : AuthStateChange() {
        override val event: String get() = "initial"
    }
    /** Same `sub`, a different user object (a link, an unlink, a refresh that changed the user, a claim). Never a `SignedIn`. */
    data class UserUpdated(val user: SendoraCloudAuthUser, val cause: AuthUserUpdatedCause) : AuthStateChange() {
        override val event: String get() = "user_updated"
    }
    /** A guest was moved into a held slot by a sign-in / `forceNew` mint / restore-over-guest. `count` = held slots now occupied. */
    data class GuestHeld(val userId: String, val count: Int) : AuthStateChange() {
        override val event: String get() = "guest_held"
    }
    /** A held slot was emptied; `reason` names the exit, `endReason` qualifies [GuestReleasedReason.DEAD]. */
    data class GuestReleased(val userId: String, val reason: GuestReleasedReason, val endReason: String? = null) : AuthStateChange() {
        override val event: String get() = "guest_released"
    }
    /** An in-process transition INTO `WITHHELD` (a refresh answered with a mismatching `project`). Never replayed. */
    data class SessionWithheld(val expectedProjectId: String, val actualProjectId: String?, val userId: String) : AuthStateChange() {
        override val event: String get() = "session_withheld"
        val reason: String get() = "project_mismatch"
    }
}

/** What the parent SDK must do when the auth slot is cleared (the `onAnonymousWipe` effect sink, one column of the commit table). */
data class AuthWipeEffects(
    /** Rotate the analytics anonymous id — only at a person boundary (explicit signOut, reset, account deletion). */
    val rotateDeviceId: Boolean,
    /** Drop the queued analytics events — only on account deletion and reset (s58.353). */
    val clearQueue: Boolean,
    /** Forget the persisted analytics `user_id`. False for `discardWithheld()`, which keeps it. */
    val clearUserId: Boolean,
)

/** Init-time machine options, resolved by `SendoraCloud.init` from [SendoraCloudConfig]. */
internal data class AuthMachineConfig(
    val projectId: String? = null,
    val expectedProjectId: String? = null,
    val autoRestoreHeldGuest: Boolean = true,
)

class SendoraCloudAuth internal constructor(
    private val client: AuthTransport,
    private val storage: AuthStore,
    private val onIdentityChange: (String?) -> Unit,
    /** The parent SDK's effect sink for a cleared slot (anon-id rotation, queue, `user_id`). */
    private val onAnonymousWipe: suspend (AuthWipeEffects) -> Unit,
    private val machine: AuthMachineConfig = AuthMachineConfig(),
    /** ADR-033 2c: nulls the parent's analytics user id IN MEMORY only; the persisted `user_id` is untouched. */
    private val onIdentityWithheld: () -> Unit = {},
    cron: RefreshCron? = null,
    private val clock: () -> Long = { System.currentTimeMillis() },
    background: ((suspend () -> Unit) -> Unit)? = null,
    /** Test seam: every emission, synchronously, in order — the listener fan-out stays asynchronous. */
    private val eventSink: ((AuthStateChange) -> Unit)? = null,
) {
    // ─── the ONE slot (§3.2) ────────────────────────────────────────────────
    private sealed class AuthSlot {
        object Empty : AuthSlot()
        data class Session(val record: AuthRecord) : AuthSlot()
        /** LIMBO_A / unreadable claim: a refresh token is on disk, the identity is not settled. */
        data class Limbo(val refreshToken: String, val accessToken: String?, val expiresAt: Long, val user: SendoraCloudAuthUser?) : AuthSlot()
        /** A stored session refused by the project guard — in memory only, never persisted (§3.2). */
        data class Withheld(val refreshToken: String, val accessToken: String?, val expiresAt: Long, val info: WithheldInfo) : AuthSlot()
    }

    @Volatile private var slot: AuthSlot = AuthSlot.Empty
    /** The K physical held slots, in storage order; `null` = free. An unparseable slot is KEPT (non-null raw, null parse). */
    private val heldSlots: Array<HeldSlot?> = arrayOfNulls(AuthKeys.HELD_SLOT_KEYS.size)
    /** B15 pending-report flag (non-secret, lives in `auth_session`). */
    @Volatile private var heldReportPending: List<String> = emptyList()
    /**
     * True once the constructor finished hydrating. `status()` is `UNKNOWN`
     * before that; `authStateReady()` resolves after it and NEVER waits on the
     * network.
     */
    @Volatile private var hydrated = false
    /**
     * Set once we have PROOF the device clock runs fast: a token the server
     * minted SECONDS AGO already reads past its own `exp`. A fresh token is
     * never genuinely expired, so the clock we measured it with is the liar.
     * Releases the `exp` guard for this process.
     *
     * ⚠ NEVER PERSIST. Re-learned for the cost of one refresh, and a stored
     * "clock is fast" belief would outlive the correction that made it false —
     * the same stale-frame bug this guard closes, one level up.
     *
     * ⚠ Without it the `exp` guard alone is a REFRESH LOOP on any clock fast by
     * more than the token TTL: every freshly-minted token reads as already
     * expired, so every call refreshes. Measured on the React Native reference
     * implementation at 10 reads -> 10 refreshes.
     */
    @Volatile private var clockSkewConfirmed = false
    /** §3.3 scheduling rule: the proactive cron does not start a refresh while an identity attempt is pending. */
    @Volatile private var identityAttemptPending = false
    private val mutex = Mutex()
    private val refreshMutex = Mutex()
    private val settleWaiters = mutableListOf<CompletableDeferred<Unit>>()
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
    // Long-lived coroutine scope for the proactive-refresh cron (s58.73), the
    // ordered listener fan-out and fire-and-forget calls. SupervisorJob so a
    // single failure doesn't kill the loop.
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val refreshSafetyMs = 30_000L
    private val cron: RefreshCron = cron ?: CoroutineRefreshCron(scope)
    private val background: (suspend () -> Unit) -> Unit = background ?: { block -> scope.launch { runCatching { block() } } }
    /** Ordered fan-out: a channel consumed by ONE coroutine, so listeners see events in emission order. */
    private val emissions = Channel<Pair<AuthStateChange, List<(AuthStateChange) -> Unit>>>(Channel.UNLIMITED)

    init {
        scope.launch {
            for ((change, listeners) in emissions) {
                for (fn in listeners) runCatching { fn(change) }
            }
        }
        hydrate()
    }

    // ─── status & synchronous readers ──────────────────────────────────────

    /**
     * The settled client state (ADR-033 §3.2). `UNKNOWN` ≠ `SIGNED_OUT` ≠
     * `WITHHELD`: [currentUser] is `null` in all three, so this is the ONLY
     * way to tell them apart. ⚠ Branch with an `else`.
     */
    fun status(): AuthStatus {
        if (!hydrated) return AuthStatus.UNKNOWN
        return when (val s = slot) {
            AuthSlot.Empty -> AuthStatus.SIGNED_OUT
            is AuthSlot.Limbo -> AuthStatus.UNKNOWN
            is AuthSlot.Withheld -> AuthStatus.WITHHELD
            is AuthSlot.Session -> if (s.record.user.isAnonymous) AuthStatus.ANONYMOUS else AuthStatus.IDENTIFIED
        }
    }

    /**
     * Resolves after hydrate with the settled status — possibly `UNKNOWN`
     * (offline with an unreadable record) or `WITHHELD`. Never waits on the
     * network; on Android hydrate runs in the constructor, so this is immediate.
     */
    suspend fun authStateReady(): AuthStatus = status()

    /** Alias kept: the current user, `null` in `UNKNOWN` / `SIGNED_OUT` / `WITHHELD`. */
    val currentUser: SendoraCloudAuthUser? get() = (slot as? AuthSlot.Session)?.record?.user

    /** Synchronous read — returns whatever's cached, even if expired; `null` in `WITHHELD`.
     *  Prefer `getAccessToken()` for transparent refresh. */
    val accessToken: String?
        get() = when (val s = slot) {
            is AuthSlot.Session -> s.record.accessToken
            is AuthSlot.Limbo -> s.accessToken
            else -> null
        }

    /**
     * The stored refresh token (an integrator journalling it before a sign-in
     * no longer needs to — the SDK holds a replaced guest itself). `null` in
     * `SIGNED_OUT` and `WITHHELD`.
     */
    fun getRefreshToken(): String? = when (val s = slot) {
        is AuthSlot.Session -> s.record.refreshToken
        is AuthSlot.Limbo -> s.refreshToken
        else -> null
    }

    /** Every held guest on this device, newest first, tokens never exposed. Best-effort (§3.2). */
    fun heldGuests(): List<HeldGuestSummary> =
        heldSlots.mapNotNull { it?.parsed }
            .sortedByDescending { it.heldAt }
            .map { HeldGuestSummary(it.userId, it.heldAt, it.autoRestore, it.project) }

    /** The newest held guest, or `null`. */
    fun heldGuest(): HeldGuestSummary? = heldGuests().firstOrNull()

    /** Why the stored session is being refused, while `status() == WITHHELD`; else `null`. */
    fun withheld(): WithheldInfo? = (slot as? AuthSlot.Withheld)?.info

    /** Lockstep spelling of [heldGuests] (RN / web / ADR-033 §3.5 `getHeldGuests()`). */
    fun getHeldGuests(): List<HeldGuestSummary> = heldGuests()

    /** Lockstep spelling of [heldGuest] (`getHeldGuest()`). */
    fun getHeldGuest(): HeldGuestSummary? = heldGuest()

    /** Lockstep spelling of [withheld] (`getWithheld()`). */
    fun getWithheld(): WithheldInfo? = withheld()

    // ─── access token (two-deadline guard, s58.281 — unchanged) ────────────

    /**
     * The cached-token guard, and the only place the two deadlines are
     * combined. Both must agree before a cached token is served:
     *
     *  1. the locally-tracked deadline (`now + expiresIn` at mint) — immune to
     *     a constantly-wrong clock, blind to a clock that MOVES;
     *  2. the token's own `exp` — immune to a clock that moves, wrong by the
     *     full offset on a constantly-wrong clock.
     *
     * Guard 2 is released once [clockSkewConfirmed] proves which failure mode
     * we are in. Reported by Word Hurdle with a token 1929s past its `exp`.
     */
    private fun canServeToken(token: String?, expiresAt: Long, nowMs: Long): Boolean {
        if (token.isNullOrEmpty() || expiresAt <= 0L) return false
        if (nowMs >= expiresAt - refreshSafetyMs) return false
        if (clockSkewConfirmed) return true
        return accessTokenExpIsFuture(token, nowMs)
    }

    private fun currentTokenAndDeadline(): Pair<String?, Long> = when (val s = slot) {
        is AuthSlot.Session -> s.record.accessToken to s.record.expiresAt
        is AuthSlot.Limbo -> s.accessToken to s.expiresAt
        else -> null to 0L
    }

    /** Guard 1 alone: does the locally-tracked deadline still claim life? */
    private fun trackedDeadlineAlive(nowMs: Long): Boolean {
        val (token, exp) = currentTokenAndDeadline()
        return !token.isNullOrEmpty() && exp > 0L && nowMs < exp - refreshSafetyMs
    }

    /** True when a cached token is unusable ONLY because `exp` contradicts a tracked deadline that still claims life. */
    private fun deadlinesDisagree(nowMs: Long): Boolean {
        val (token, exp) = currentTokenAndDeadline()
        return trackedDeadlineAlive(nowMs) && !canServeToken(token, exp, nowMs)
    }

    private fun learnClockSkewFrom(freshToken: String, nowMs: Long) {
        if (!accessTokenExpIsFuture(freshToken, nowMs)) clockSkewConfirmed = true
    }

    /**
     * Refresh — and when the two deadlines disagree, let the token that comes
     * back say which one was lying.
     *
     * ⚠ THE TIMING IS THE MECHANISM, and the obvious placement is wrong.
     * Probing at every mint site looks equivalent and is not: in the reported
     * failure the token was MINTED while the clock was fast and only read after
     * the correction, so a mint-time probe records "clock is fast" and then
     * waves through the very token the guard exists to refuse. Probing only on
     * a refresh performed BECAUSE `exp` contradicted a live tracked deadline
     * separates the cases.
     */
    private suspend fun refreshAndReconcile(nowMs: Long, staleToken: String? = null): String? {
        val reconciling = deadlinesDisagree(nowMs)
        val token = refreshAccessToken(staleToken)
        if (reconciling && !token.isNullOrEmpty()) {
            learnClockSkewFrom(token, clock())
        }
        return token
    }

    /**
     * Returns a non-expired access token, refreshing single-flight when the
     * cached one is past expiry (or when the two deadlines disagree). Also
     * drives the single gap-fill refresh of an `UNKNOWN` record. `null` when
     * signed out and — ADR-033 2c — in `WITHHELD`: a withheld session's tokens
     * are never served, never refreshed.
     *
     * @param forceRefresh skip the cache when the caller has out-of-band
     *   evidence that the tracked deadline is wrong (it decoded `exp` itself,
     *   or ate a 401). Does NOT bypass the refresh mutex or the backoff
     *   cooldown.
     */
    @JvmOverloads
    suspend fun getAccessToken(forceRefresh: Boolean = false): String? = guardedValue {
        when (slot) {
            is AuthSlot.Withheld, AuthSlot.Empty -> return@guardedValue null
            else -> Unit
        }
        val nowMs = clock()
        val (token, expiresAt) = currentTokenAndDeadline()
        // UNKNOWN (LIMBO_A / unreadable claim) never serves its cached token: the
        // identity behind it is not settled, so the call IS the gap-fill.
        val settled = slot is AuthSlot.Session
        if (settled && !forceRefresh && canServeToken(token, expiresAt, nowMs)) return@guardedValue token
        // `forceRefresh` names the token the caller distrusts, so the re-check
        // under the refresh mutex cannot hand that same token straight back
        // (the pre-4.26.0 re-check did, which made `forceRefresh` a no-op on a
        // token whose deadline still claimed life). A rotation that landed
        // meanwhile is a DIFFERENT token and is served without a second refresh.
        refreshAndReconcile(nowMs, staleToken = if (forceRefresh || !settled) token ?: STALE_NONE else null)
    }

    // ─── listeners ─────────────────────────────────────────────────────────

    /**
     * Register a callback fired when the backend retires an anon
     * `user_id` during a signin on this device. Returns an unsubscribe lambda.
     *
     * ⚠ LEGACY after ADR-033 (4.26.0). A 4.26.0 sign-in never presents the
     * guest's refresh token, so the server never retires a guest for it:
     * signIn / loginSocial / **signInWithPlayGames** / challengeMfa /
     * verifyMagicLink / verifyEmailOtp / passkey authenticate all HOLD a
     * replaced guest on this device instead (`AuthStateChange.GuestHeld`,
     * [heldGuests]). The listener stays registered and compiles; it fires only
     * if the SERVER reports a retirement (`retiredAnonUserId` on a response),
     * which happens for pre-4.26.0 installs only. Read [heldGuests] for the
     * device-local answer. For server-pipeline cleanup subscribe to the
     * `auth.device_takeover` webhook (legacy installs) and `auth.user_merged`.
     */
    fun onDeviceTakeover(listener: (DeviceTakeoverEvent) -> Unit): () -> Unit {
        val key = java.util.UUID.randomUUID()
        takeoverListeners[key] = listener
        return { takeoverListeners.remove(key) }
    }

    /** The most recent takeover the SDK observed in this session, or null if none. */
    fun getLastDeviceTakeover(): DeviceTakeoverEvent? = lastTakeover

    /**
     * Internal — fired only when a response carries `retiredAnonUserId`, which
     * a 4.26.0 request never causes. Validates UUID shape before firing (a
     * tampered value handed to a path-interpolating listener is an injection
     * sink in the host app).
     */
    internal fun fireDeviceTakeover(retiredAnonUserId: String, identifiedUserId: String) {
        if (retiredAnonUserId.isEmpty()) return
        if (!isCanonicalUuid(retiredAnonUserId)) return
        val evt = DeviceTakeoverEvent(
            retiredAnonUserId = retiredAnonUserId,
            identifiedUserId = identifiedUserId,
            at = clock(),
        )
        lastTakeover = evt
        for (fn in takeoverListeners.values.toList()) {
            runCatching { fn(evt) }
        }
    }

    /**
     * Subscribe to deletion-cancelled events (s58.269): fires when a sign-in
     * cancelled a pending self-service account deletion within its grace window
     * (the account is restored, same user_id). Also surfaced as
     * [SignInResult.Done.reactivated]. Returns an unsubscribe function.
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
     * sign-in has happened this session (s58.278). LEGACY: a 4.26.0 sign-in
     * never presents the guest, so the server answers [AnonRetirementOutcome.NONE];
     * the replaced guest is in [heldGuests].
     */
    fun getLastAnonRetirement(): AnonRetirementOutcome? = lastAnonRetirement

    internal fun fireDeletionCancelled(identifiedUserId: String) {
        val evt = DeletionCancelledEvent(userId = identifiedUserId, at = clock())
        lastDeletionCancelled = evt
        for (fn in deletionCancelledListeners.values.toList()) {
            runCatching { fn(evt) }
        }
    }

    /**
     * Subscribe to every auth-state transition — the single stream that answers
     * "what happened to my session?". Returns an unsubscribe lambda.
     *
     * Replays the settled boot state to the new subscriber exactly once as
     * [AuthStateChange.Initial] — INCLUDING `SIGNED_OUT`, `UNKNOWN` and
     * `WITHHELD`, which the 4.12.0 replay could not express — and, when a
     * session is on disk, the legacy [AuthStateChange.SignedIn] replay the
     * 4.12.0 contract documented (ADR-023: never remove an emission a
     * subscriber may key on). Nothing is ever emitted before hydrate completes.
     *
     * A FAILED attempt emits nothing — the session is unchanged, so there is no
     * transition to report. A rotation emits nothing. Listeners are best-effort
     * (a throwing listener is swallowed), dispatched OFF the caller's coroutine
     * in emission order, and never affect auth state. This is a transition
     * stream, not a health signal (s58.355 A6).
     */
    fun onAuthStateChanged(listener: (AuthStateChange) -> Unit): () -> Unit {
        val key = java.util.UUID.randomUUID()
        authStateListeners[key] = listener
        if (hydrated) {
            val user = currentUser
            runCatching { listener(AuthStateChange.Initial(status(), user, withheld())) }
            user?.let { runCatching { listener(AuthStateChange.SignedIn(it)) } }
        }
        return { authStateListeners.remove(key) }
    }

    /**
     * Fan a state change out to subscribers. Never throws. Dispatched OFF the
     * caller's coroutine because every emission site runs while `mutex` is
     * held: a listener that calls back into any suspend auth method would
     * otherwise deadlock permanently. Order is preserved (one consumer).
     */
    private fun emitAuthState(change: AuthStateChange) {
        eventSink?.invoke(change)
        val snapshot = authStateListeners.values.toList()
        if (snapshot.isEmpty()) return
        emissions.trySend(change to snapshot)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MINT (§3.3 rows 6–11)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Return the session this device already holds, or establish one.
     *
     *  - `ANONYMOUS` / `IDENTIFIED` → the current user, no network (the 1.29 /
     *    4.25.0 A2 guard as one table row). `forceNew = true` is the single
     *    explicit replace: a current GUEST is HELD on this device
     *    (`GuestHeld`), an identified account is left server-side, and a fresh
     *    guest is minted.
     *  - `SIGNED_OUT` → with `autoRestoreHeldGuest` (default) and an eligible
     *    held guest, the NEWEST one is RESTORED instead of minting — visibly:
     *    `SignedIn(cause = RESTORE)` then `GuestReleased(RESTORED)`. A held
     *    guest the server reports gone is released (`GuestReleased(DEAD)`) and
     *    the next is tried; none left → a fresh mint in the same call, so this
     *    never resolves without a session because of a dead slot. Otherwise
     *    `POST /anonymous` (with a per-attempt `mintKey`, so a retry after a
     *    process death gets the same guest back).
     *  - `UNKNOWN` → QUEUED until the single gap-fill refresh settles the
     *    status (offline it waits; it never mints over an unsettled record).
     *  - `WITHHELD` → rejects `SESSION_WITHHELD`.
     *
     * The held-slot bound is enforced HERE: T = held + (current guest ? 1 : 0)
     * ≤ 5. `forceNew` at the cap, or no eligible guest at the cap, fails with
     * [SendoraCloudAuthError.HeldGuestLimit] and mutates nothing — the one boot
     * corner that does not self-heal (§8-Q22): restore or discard a held guest.
     */
    suspend fun signInAnonymously(
        name: String? = null,
        metadata: Map<String, Any>? = null,
        forceNew: Boolean = false,
    ): Result<SendoraCloudAuthUser> {
        awaitSettledIfUnknown()
        return serialize {
            if (!storage.isSecureAvailable) {
                return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable(
                    "EncryptedSharedPreferences unavailable — refusing to mint a session that can't be persisted securely"
                ))
            }
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            val existing = currentUser
            if (!forceNew && existing != null) {
                return@serialize Result.success(existing)
            }
            when (status()) {
                AuthStatus.UNKNOWN -> Result.failure(SendoraCloudAuthError.Network("Session state is unknown — the stored session could not be refreshed"))
                AuthStatus.ANONYMOUS, AuthStatus.IDENTIFIED -> {
                    // `mint.force_new_at_cap`: T = |held| + (current anonymous ? 1 : 0).
                    // At T == K the current guest has no free slot to be HELD in.
                    if (totalGuests() >= HELD_CAPACITY) {
                        return@serialize Result.failure(heldLimitError())
                    }
                    mintFresh(name, metadata, holdCurrentGuest = true)
                }
                else -> if (forceNew) {
                    if (totalGuests() >= HELD_CAPACITY) Result.failure(heldLimitError()) else mintFresh(name, metadata, holdCurrentGuest = false)
                } else {
                    mintOrRestore(name, metadata)
                }
            }
        }
    }

    /** Alias of [signInAnonymously] with no options — "make sure I have a session". */
    suspend fun ensureSession(): Result<SendoraCloudAuthUser> = signInAnonymously()

    /** The `SIGNED_OUT | MINT` rows: restore the newest eligible held guest, else mint. */
    private suspend fun mintOrRestore(name: String?, metadata: Map<String, Any>?): Result<SendoraCloudAuthUser> {
        val eligible = eligibleHeldIndicesNewestFirst()
        val held = heldCount()
        if (eligible.isEmpty()) {
            return if (held >= HELD_CAPACITY) Result.failure(heldLimitError()) else mintFresh(name, metadata, holdCurrentGuest = false)
        }
        if (!machine.autoRestoreHeldGuest && held < HELD_CAPACITY) {
            return mintFresh(name, metadata, holdCurrentGuest = false)
        }
        for (index in eligible) {
            when (val r = restoreSlot(index)) {
                is RestoreOutcome.Restored -> return Result.success(r.user)
                // Released (dead) or kept (reuse / absent endReason / project claim
                // learned on the response): try the next-newest eligible slot.
                is RestoreOutcome.Dead, is RestoreOutcome.Kept, is RestoreOutcome.Mismatch -> continue
                is RestoreOutcome.Failed -> return Result.failure(r.error)
            }
        }
        return if (heldCount() >= HELD_CAPACITY) Result.failure(heldLimitError()) else mintFresh(name, metadata, holdCurrentGuest = false)
    }

    /** `POST /anonymous` (+ B10 `mintKey`) → ProjectGuard on the response → install (`SignedIn(MINT)`). */
    private suspend fun mintFresh(name: String?, metadata: Map<String, Any>?, holdCurrentGuest: Boolean): Result<SendoraCloudAuthUser> =
        identityAttempt { expect ->
            val mintKey = storage.plainGet(AuthKeys.MINT_KEY) ?: newMintKey().also { commit(AuthTx.MintKey(it)) }
            val body = mutableMapOf<String, Any?>("mintKey" to mintKey)
            name?.let { body["name"] = it }
            metadata?.let { body["metadata"] = it }
            val response = client.post("/auth-service/anonymous", body)
            parseError(response)?.let { return@identityAttempt Result.failure(it) }
            val record = parseRecord(response, clock())
                ?: return@identityAttempt Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
            val tx = AuthTx.Install(
                record = record,
                reason = InstallReason.MINT,
                expectIdentity = expect,
                holdPreviousGuest = holdCurrentGuest,
                revokePreviousIdentified = true,
                emit = Emit.SignedIn(AuthSignedInCause.MINT),
            )
            when (val outcome = commitIdentity(tx)) {
                is CommitOutcome.Applied -> Result.success(record.user)
                else -> Result.failure(outcome.asError(record))
            }
        }

    // ═══════════════════════════════════════════════════════════════════════
    // SIGN-IN / SWITCH (§3.3 rows 18–19) — legacy signatures, unchanged
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Sign in to an existing account. A plain SWITCH: the request carries the
     * credential and NOTHING about this device's guest (INV-3). On success a
     * current guest is HELD on this device (`GuestHeld` then ONE
     * `SignedIn(cause = SIGN_IN)`, no `SignedOut`); a different identified
     * account's session is revoked fire-and-forget. A failed attempt — wrong
     * password, 429, airplane mode — leaves the caller exactly as found.
     * Queued in `UNKNOWN`; rejects `SESSION_WITHHELD`.
     */
    suspend fun signIn(email: String, password: String): Result<SendoraCloudAuthUser> =
        switchWithLegacyResult("/auth-service/login", mapOf("email" to email, "password" to password))

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
     * Like `signIn()` but discriminates the MFA-required path. The current
     * session survives the challenge: the response may be a challenge rather
     * than a session, and a user who abandons the TOTP prompt keeps their
     * account (the context lives in the result, never in a nullable field).
     */
    suspend fun signInWithMfaSupport(email: String, password: String): Result<SignInOutcome> {
        awaitSettledIfUnknown()
        return serialize {
            if (!storage.isSecureAvailable) {
                return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
            }
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            performSwitch("/auth-service/login", mapOf("email" to email, "password" to password)).map { r ->
                when (r) {
                    is SignInResult.Done -> SignInOutcome.Authenticated(r.user)
                    is SignInResult.MfaRequired -> SignInOutcome.MfaRequired(r.challengeToken, mfaUserIdHint ?: "")
                }
            }
        }
    }

    /** `data.user.id` of the last MFA challenge envelope — carried for [SignInOutcome.MfaRequired.userId] only. */
    @Volatile private var mfaUserIdHint: String? = null

    /**
     * Exchange the MFA challenge token + TOTP/recovery code for a session (a
     * SIGN-IN continuation — the guest, if any, is held when the session
     * installs). A wrong or expired code leaves the current session intact.
     */
    suspend fun challengeMfa(challengeToken: String, code: String): Result<SendoraCloudAuthUser> =
        switchWithLegacyResult("/auth-service/mfa/challenge", mapOf("challengeToken" to challengeToken, "code" to code))

    // --- Magic link ---

    suspend fun sendMagicLink(email: String): Result<Unit> = guardedResult {
        val response = client.post("/auth-service/magic-link/request", mapOf("email" to email))
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    // --- Social sign-in (8 providers) ---

    /**
     * Verify an IdP-issued credential and mint a Sendora session. Provider is
     * one of: google, github, apple, microsoft, linkedin, facebook, twitter,
     * discord. Pass either `code` + `redirectUri` (authorization-code flow) OR
     * `idToken` (native style).
     *
     * `link = true` (ADR-025 → ADR-033 INV-14): a client ROUTING hint, never a
     * wire field. From a GUEST or an IDENTIFIED session the call goes to
     * `/me/link/social` and attaches to the CURRENT account (same `sub`); over
     * identified it attaches or errors — it never switches. Already attached →
     * a quiet success with no event. Owned by another account → see
     * [onCredentialInUse]. A session too old to attach a NEW credential fails
     * with kind `RECENT_AUTH_REQUIRED` (403). From `SIGNED_OUT` there is nothing
     * to attach to and the call is a plain sign-in (reinstall recovery).
     * `link = false` is a plain SWITCH: a current guest is held on-device.
     */
    suspend fun loginSocial(
        provider: String,
        code: String? = null,
        idToken: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
        appleFirstName: String? = null,
        appleLastName: String? = null,
        link: Boolean = false,
        /**
         * What to do when `link = true` collides with another account's identity:
         * [CredentialCollisionPolicy.ADOPT] falls through to a plain switch (a
         * guest is HELD); null or [CredentialCollisionPolicy.REJECT] fails with
         * [SendoraCloudAuthError.CredentialInUse] so the app can ask the player.
         */
        onCredentialInUse: CredentialCollisionPolicy? = null,
    ): Result<SendoraCloudAuthUser> {
        val credential = Credential.Social(provider, code, idToken, redirectUri, codeVerifier, appleFirstName, appleLastName)
        return legacyCredentialed(credential, link, onCredentialInUse)
    }

    suspend fun signInWithGoogle(code: String, redirectUri: String, link: Boolean = false) =
        loginSocial(provider = "google", code = code, redirectUri = redirectUri, link = link)

    /**
     * Google Play Games sign-in (email-less, player-keyed). Pass the
     * serverAuthCode from
     * `PlayGames.getGamesSignInClient(activity).requestServerSideAccess(webClientId, false)`.
     * `link = true` attaches the player identity to the CURRENT account (guest
     * or identified, same user id) — see [loginSocial]; `link = false` switches
     * and holds a current guest on-device.
     */
    suspend fun signInWithPlayGames(
        serverAuthCode: String,
        link: Boolean = false,
        onCredentialInUse: CredentialCollisionPolicy? = null,
    ): Result<SendoraCloudAuthUser> =
        legacyCredentialed(Credential.PlayGames(serverAuthCode), link, onCredentialInUse)

    suspend fun signInWithGitHub(code: String, redirectUri: String) =
        loginSocial(provider = "github", code = code, redirectUri = redirectUri)

    /** Apple Sign In. Pass `idToken` from the native flow + name fields on first sign-in. `link` = attach to the current account. */
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

    /** A magic-link token is routinely expired or pre-fetched by a mail scanner; a rejection costs the current session nothing. */
    suspend fun verifyMagicLink(token: String): Result<SendoraCloudAuthUser> =
        switchWithLegacyResult("/auth-service/magic-link/verify", mapOf("token" to token))

    // --- Email OTP (6-digit cross-device code) ---

    suspend fun sendEmailOtp(email: String): Result<Unit> = guardedResult {
        val response = client.post("/auth-service/email-otp/request", mapOf("email" to email))
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    /** A mistyped code is the common outcome; the current session survives it. */
    suspend fun verifyEmailOtp(email: String, code: String): Result<SendoraCloudAuthUser> =
        switchWithLegacyResult("/auth-service/email-otp/verify", mapOf("email" to email, "code" to code))

    // ═══════════════════════════════════════════════════════════════════════
    // TYPED VERBS (ADR-033 §3.5, additive)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Sign in with a typed [Credential] — the SWITCH verb. Never attaches, never
     * sends a guest hint; a current guest is HELD (`previous.held == true`), a
     * different identified account's session is revoked. `MfaRequired` carries
     * the challenge; `verify(code)` completes it.
     */
    suspend fun signInWith(credential: Credential): Result<SignInResult> {
        awaitSettledIfUnknown()
        return serialize {
            if (!storage.isSecureAvailable) {
                return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
            }
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            val (path, body) = switchRequest(credential)
            performSwitch(path, body)
        }
    }

    /**
     * Attach a credential to the CURRENT account — the ONLY upgrade (INV-4),
     * `/me/link/…` on the Bearer session, same `sub`. From a guest the account
     * is promoted in place (`upgraded == true`, rotated tokens installed, ONE
     * `UserUpdated(cause = LINK)`); from an identified account it attaches
     * (`UserUpdated(LINK)`) or is a quiet `alreadyLinked` no-op. Collisions and
     * stale sessions are RESULTS, not failures, with nothing mutated. Linkable:
     * [Credential.Password], [Credential.Social], [Credential.PlayGames].
     * Fails `Unauthorized` when signed out (nothing to attach to — use
     * [signInWith]); queued in `UNKNOWN`; rejects `SESSION_WITHHELD`.
     */
    suspend fun link(credential: Credential): Result<LinkResult> {
        awaitSettledIfUnknown()
        return serialize {
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            val req = linkRequest(credential)
                ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown(
                    "This credential kind cannot be linked; use signInWith() or SendoraCloud.passkeys.register()",
                    code = "NOT_LINKABLE", kind = SendoraCloudAuthErrorKind.CONFIG,
                ))
            performLink(req.path, req.body, req.provider, credential, legacySignedIn = false)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UPGRADE (§3.3 rows 15–17)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Create an account, routed by status (never calls `/upgrade`):
     *  - `ANONYMOUS` → `POST /me/link/email` on the Bearer session: the guest is
     *    promoted in place (same user id) and — legacy signature — emits ONE
     *    `SignedIn(cause = LINK)`. A taken email fails [SendoraCloudAuthError.EmailAlreadyTaken].
     *  - `SIGNED_OUT` → `POST /signup`.
     *  - `IDENTIFIED` → [SendoraCloudAuthError.AlreadyIdentified] LOCALLY, no
     *    round-trip (ADR-030 §4): use `linkEmailPassword()` or sign out first.
     *  - `UNKNOWN` → waits for the status to settle; `WITHHELD` → rejects.
     */
    suspend fun signUp(
        email: String,
        password: String,
        name: String? = null,
        metadata: Map<String, Any>? = null,
    ): Result<SendoraCloudAuthUser> {
        awaitSettledIfUnknown()
        return serialize {
            if (!storage.isSecureAvailable) {
                return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable(
                    "EncryptedSharedPreferences unavailable — refusing to persist auth tokens"
                ))
            }
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            when (status()) {
                AuthStatus.IDENTIFIED -> Result.failure(SendoraCloudAuthError.AlreadyIdentified(
                    "Already signed in. Use linkEmailPassword() to add a password to this account, or sign out first."
                ))
                AuthStatus.ANONYMOUS -> {
                    val body = mutableMapOf<String, Any?>("email" to email, "password" to password)
                    name?.let { body["name"] = it }
                    performLink("/auth-service/me/link/email", body, "password", Credential.Password(email, password), legacySignedIn = true)
                        .fold(
                            onSuccess = { r ->
                                when (r) {
                                    is LinkResult.Done -> Result.success(r.user)
                                    is LinkResult.CredentialInUse -> Result.failure(SendoraCloudAuthError.EmailAlreadyTaken(
                                        "An account with this email already exists", "CREDENTIAL_IN_USE", 409,
                                    ))
                                    LinkResult.RecentAuthRequired -> Result.failure(SendoraCloudAuthError.Unknown(
                                        "Recent authentication required", code = "RECENT_AUTH_REQUIRED", status = 403,
                                    ))
                                }
                            },
                            onFailure = { Result.failure(it) },
                        )
                }
                AuthStatus.SIGNED_OUT -> {
                    val body = mutableMapOf<String, Any?>("email" to email, "password" to password)
                    name?.let { body["name"] = it }
                    metadata?.let { body["metadata"] = it }
                    performSwitch("/auth-service/signup", body).map { (it as SignInResult.Done).user }
                }
                else -> Result.failure(SendoraCloudAuthError.Network("Session state is unknown — the stored session could not be refreshed"))
            }
        }
    }

    // --- Identity linking (ADR-030, legacy signatures) ---
    //
    // Attach a SECOND credential to the CURRENT signed-in account, preserving the
    // same user id (sub). Bearer-authenticated. From an identified account there
    // is NO token rotation; from a guest the account is promoted in place and
    // the rotated pair is installed (the old refresh token is revoked
    // server-side). Collision -> CredentialInUse (never merges). Already
    // attached -> quiet success, no event. Emits `UserUpdated(cause = LINK)`.

    /** Link email + password to the current account (sub preserved). */
    suspend fun linkEmailPassword(email: String, password: String): Result<SendoraCloudAuthUser> =
        legacyLink(Credential.Password(email, password))

    /** Link an OAuth social identity. Pass a native `idToken` OR a web `code` + `redirectUri`. */
    suspend fun linkSocial(
        provider: String,
        idToken: String? = null,
        code: String? = null,
        redirectUri: String? = null,
    ): Result<SendoraCloudAuthUser> =
        legacyLink(Credential.Social(provider = provider, code = code, idToken = idToken, redirectUri = redirectUri))

    /** Convenience: link a Google identity (native `idToken`, or web `code`+`redirectUri`). */
    suspend fun linkGoogle(idToken: String? = null, code: String? = null, redirectUri: String? = null): Result<SendoraCloudAuthUser> =
        linkSocial("google", idToken, code, redirectUri)

    /** Convenience: link an Apple identity. */
    suspend fun linkApple(idToken: String? = null, code: String? = null, redirectUri: String? = null): Result<SendoraCloudAuthUser> =
        linkSocial("apple", idToken, code, redirectUri)

    /** Link a Google Play Games identity to the current account (same input as [signInWithPlayGames]). */
    suspend fun linkPlayGames(serverAuthCode: String): Result<SendoraCloudAuthUser> =
        legacyLink(Credential.PlayGames(serverAuthCode))

    /** The `link*()` legacy wrappers: typed outcomes become the shipped error classes. */
    private suspend fun legacyLink(credential: Credential): Result<SendoraCloudAuthUser> {
        awaitSettledIfUnknown()
        return serialize {
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            if (status() == AuthStatus.SIGNED_OUT) {
                return@serialize Result.failure(SendoraCloudAuthError.Unauthorized("Sign in before linking a credential"))
            }
            val req = linkRequest(credential) ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Not linkable", code = "NOT_LINKABLE"))
            performLink(req.path, req.body, req.provider, credential, legacySignedIn = false).fold(
                onSuccess = { r -> legacyLinkResult(r, credential, onCredentialInUse = null) },
                onFailure = { Result.failure(it) },
            )
        }
    }

    /**
     * The `link = true` legacy sign-ins (`loginSocial`, `signInWithPlayGames`):
     * `ANONYMOUS` | `IDENTIFIED` → LINK row (attach-or-typed-error);
     * `SIGNED_OUT` → plain SIGN-IN; `link = false` → plain SIGN-IN.
     */
    private suspend fun legacyCredentialed(
        credential: Credential,
        link: Boolean,
        onCredentialInUse: CredentialCollisionPolicy?,
    ): Result<SendoraCloudAuthUser> {
        awaitSettledIfUnknown()
        return serialize {
            if (!storage.isSecureAvailable) {
                return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
            }
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            val st = status()
            if (link && (st == AuthStatus.ANONYMOUS || st == AuthStatus.IDENTIFIED)) {
                val req = linkRequest(credential) ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Not linkable", code = "NOT_LINKABLE"))
                performLink(req.path, req.body, req.provider, credential, legacySignedIn = true).fold(
                    onSuccess = { r -> legacyLinkResult(r, credential, onCredentialInUse) },
                    onFailure = { Result.failure(it) },
                )
            } else {
                val (path, body) = switchRequest(credential)
                performSwitch(path, body).map { (it as SignInResult.Done).user }
            }
        }
    }

    /**
     * Map a typed [LinkResult] onto the legacy `Result<User>` contract. ADOPT =
     * the explicit consent to switch into the owning account: the same
     * credential the link just presented (fresh by construction) goes to the
     * plain sign-in route — INV-14's bound switch, with `mutex` already held.
     */
    private suspend fun legacyLinkResult(
        r: LinkResult,
        credential: Credential,
        onCredentialInUse: CredentialCollisionPolicy?,
    ): Result<SendoraCloudAuthUser> = when (r) {
        is LinkResult.Done -> Result.success(r.user)
        is LinkResult.CredentialInUse ->
            if (onCredentialInUse == CredentialCollisionPolicy.ADOPT) {
                val (path, body) = switchRequest(credential)
                performSwitch(path, body).map { (it as SignInResult.Done).user }
            } else {
                Result.failure(SendoraCloudAuthError.CredentialInUse(
                    "This credential already belongs to another account", "CREDENTIAL_IN_USE", 409, r.provider, r.collision,
                ))
            }
        LinkResult.RecentAuthRequired -> Result.failure(SendoraCloudAuthError.Unknown(
            "Recent authentication required", code = "RECENT_AUTH_REQUIRED", status = 403,
        ))
    }

    private class LinkRequest(val path: String, val body: Map<String, Any?>, val provider: String)

    /** The `/me/link/…` request for a linkable credential; `null` for kinds with no link route. */
    private fun linkRequest(c: Credential): LinkRequest? = when (c) {
        is Credential.Password -> LinkRequest("/auth-service/me/link/email", mapOf("email" to c.email, "password" to c.password), "password")
        is Credential.Social -> LinkRequest("/auth-service/me/link/social", socialBody(c), c.provider)
        is Credential.PlayGames -> LinkRequest("/auth-service/me/link/play-games", mapOf("serverAuthCode" to c.serverAuthCode), "playgames")
        else -> null
    }

    /** The plain sign-in request for a credential. ⚠ INV-3: no guest hint field exists to add. */
    private fun switchRequest(c: Credential): Pair<String, Map<String, Any?>> = when (c) {
        is Credential.Password -> "/auth-service/login" to mapOf("email" to c.email, "password" to c.password)
        is Credential.Social -> "/auth-service/login/social" to socialBody(c)
        is Credential.PlayGames -> "/auth-service/login/play-games" to mapOf("serverAuthCode" to c.serverAuthCode)
        is Credential.MagicLink -> "/auth-service/magic-link/verify" to mapOf("token" to c.token)
        is Credential.EmailOtp -> "/auth-service/email-otp/verify" to mapOf("email" to c.email, "code" to c.code)
        is Credential.Passkey -> "/auth-service/passkeys/authenticate/finish" to mapOf("response" to c.assertion)
        is Credential.Mfa -> "/auth-service/mfa/challenge" to mapOf("challengeToken" to c.challengeToken, "code" to c.code)
    }

    private fun socialBody(c: Credential.Social): Map<String, Any?> = buildMap {
        put("provider", c.provider)
        c.code?.let { put("code", it) }
        c.idToken?.let { put("idToken", it) }
        c.redirectUri?.let { put("redirectUri", it) }
        c.codeVerifier?.let { put("codeVerifier", it) }
        if (c.appleFirstName != null || c.appleLastName != null) {
            put("appleName", buildMap<String, String> {
                c.appleFirstName?.let { put("firstName", it) }
                c.appleLastName?.let { put("lastName", it) }
            })
        }
    }

    /** Legacy `Result<User>` wrapper over a plain switch (queued in UNKNOWN, rejected in WITHHELD). */
    private suspend fun switchWithLegacyResult(path: String, body: Map<String, Any?>): Result<SendoraCloudAuthUser> {
        awaitSettledIfUnknown()
        return serialize {
            if (!storage.isSecureAvailable) {
                return@serialize Result.failure(SendoraCloudAuthError.SecureStorageUnavailable("EncryptedSharedPreferences unavailable"))
            }
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            performSwitch(path, body).fold(
                onSuccess = { r ->
                    when (r) {
                        is SignInResult.Done -> Result.success(r.user)
                        is SignInResult.MfaRequired -> Result.failure(SendoraCloudAuthError.Unknown(
                            "MFA required — use signInWithMfaSupport() and challengeMfa()", code = "MFA_REQUIRED",
                            kind = SendoraCloudAuthErrorKind.INVALID_CREDENTIAL,
                        ))
                    }
                },
                onFailure = { Result.failure(it) },
            )
        }
    }

    /**
     * The SIGN-IN / SWITCH row, with `mutex` held. Awaits any in-flight refresh
     * at start AND at commit; the request carries no guest hint; the result is
     * applied only if the session it was derived from is still current (sid
     * CAS); a current guest is HELD (slot written FIRST), a different identified
     * account is revoked; emits `GuestHeld` (if held) then ONE `SignedIn`.
     */
    private suspend fun performSwitch(path: String, body: Map<String, Any?>): Result<SignInResult> = identityAttempt { expect ->
        val response = client.post(path, body)
        parseError(response)?.let { return@identityAttempt Result.failure(it) }
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?>
            ?: return@identityAttempt Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        if (data["mfaRequired"] == true) {
            val challengeToken = data["mfaChallengeToken"] as? String
                ?: return@identityAttempt Result.failure(SendoraCloudAuthError.Unknown("Missing mfaChallengeToken"))
            @Suppress("UNCHECKED_CAST")
            mfaUserIdHint = (data["user"] as? Map<String, Any?>)?.get("id") as? String
            // Nothing minted yet; the current session stays live. The context
            // lives in the result — abandoning the prompt leaves everything as is.
            return@identityAttempt Result.success(SignInResult.MfaRequired(challengeToken) { code ->
                challengeMfaTyped(challengeToken, code)
            })
        }
        val record = parseRecord(response, clock())
            ?: return@identityAttempt Result.failure(SendoraCloudAuthError.Unknown("Malformed response"))
        val previous = currentUser
        val tx = AuthTx.Install(
            record = record,
            reason = InstallReason.SIGN_IN,
            expectIdentity = expect,
            holdPreviousGuest = true,
            revokePreviousIdentified = true,
            emit = Emit.SignedIn(AuthSignedInCause.SIGN_IN),
        )
        when (val outcome = commitIdentity(tx)) {
            is CommitOutcome.Applied -> {
                recordLegacyResponseSignals(data, record.user)
                Result.success(SignInResult.Done(
                    user = record.user,
                    previous = previous?.let { PreviousSession(it.id, it.isAnonymous, outcome.heldPrevious) },
                    reactivated = data["reactivatedFromDeletion"] as? Boolean == true,
                ))
            }
            else -> Result.failure(outcome.asError(record))
        }
    }

    /** `SignInResult.MfaRequired.verify` — a SIGN-IN continuation under the mutex. */
    private suspend fun challengeMfaTyped(challengeToken: String, code: String): Result<SignInResult> = serialize {
        rejectIfWithheld()?.let { return@serialize Result.failure(it) }
        performSwitch("/auth-service/mfa/challenge", mapOf("challengeToken" to challengeToken, "code" to code))
    }

    /**
     * The LINK rows, with `mutex` held. `POST /me/link/…` on a FRESH Bearer;
     * 409 → typed `CredentialInUse` (bound `switchAccount`); 403
     * `RECENT_AUTH_REQUIRED` → typed; `alreadyLinked` → quiet (no write, no
     * event); `upgraded` → install the rotated pair, same `sub` (legacy-signature
     * callers emit `SignedIn(LINK)`, `link*()`/`link()` emit `UserUpdated(LINK)`,
     * never both); attached → `UserUpdated(LINK)`.
     */
    private suspend fun performLink(
        path: String,
        body: Map<String, Any?>,
        provider: String,
        credential: Credential,
        legacySignedIn: Boolean,
    ): Result<LinkResult> = identityAttempt { expect ->
        val token = getAccessToken()
            ?: return@identityAttempt Result.failure(SendoraCloudAuthError.Unauthorized("Sign in before linking a credential"))
        val headers = mapOf("Authorization" to "Bearer $token")
        val response = client.post(path, body, headers)
        parseError(response)?.let { err ->
            val details = objectField(objectField(response?.get("error"))?.get("details"))
            return@identityAttempt when {
                err.code == "CREDENTIAL_IN_USE" -> {
                    val refusedAt = clock()
                    val refusedProvider = details?.get("provider") as? String ?: provider
                    val collision = LinkCollision.fromWire(details?.get("collision") as? String)
                    Result.success(LinkResult.CredentialInUse(refusedProvider, collision) { refetch ->
                        switchFromRefusedLink(credential, refusedAt, refetch)
                    })
                }
                err.code == "RECENT_AUTH_REQUIRED" || err.kind == SendoraCloudAuthErrorKind.RECENT_AUTH_REQUIRED ->
                    Result.success(LinkResult.RecentAuthRequired)
                else -> Result.failure(err)
            }
        }
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?>
            ?: return@identityAttempt Result.failure(SendoraCloudAuthError.Unknown("Malformed link response"))
        @Suppress("UNCHECKED_CAST")
        val user = (data["user"] as? Map<String, Any?>)?.let(AuthCodecs::userFromMap)
            ?: return@identityAttempt Result.failure(SendoraCloudAuthError.Unknown("Malformed link response"))
        if (data["alreadyLinked"] == true) {
            // B13: a quiet 200 — no write, no event, no revoke, no step-up.
            return@identityAttempt Result.success(LinkResult.Done(user, upgraded = false, alreadyLinked = true))
        }
        val emit = if (legacySignedIn) Emit.SignedIn(AuthSignedInCause.LINK) else Emit.UserUpdated(AuthUserUpdatedCause.LINK)
        val rotated = if (data["upgraded"] == true) parseRecord(response, clock()) else null
        if (rotated != null) {
            // A guest promoted in place: the server rotated the session (the
            // `is_anonymous` claim changed) and revoked the old refresh token —
            // installing the pair is NOT optional.
            val tx = AuthTx.Install(
                record = rotated,
                reason = InstallReason.UPGRADE,
                expectIdentity = expect,
                holdPreviousGuest = false,
                revokePreviousIdentified = false,
                emit = emit,
            )
            return@identityAttempt when (val outcome = commitIdentity(tx)) {
                is CommitOutcome.Applied -> Result.success(LinkResult.Done(rotated.user, upgraded = true, alreadyLinked = false))
                else -> Result.failure(outcome.asError(rotated))
            }
        }
        if (!commitIdentityUser(AuthTx.UpdateUser(user, AuthUserUpdatedCause.LINK, expect))) {
            return@identityAttempt Result.failure(SendoraCloudAuthError.Superseded("The session changed while the link was in flight"))
        }
        Result.success(LinkResult.Done(user, upgraded = false, alreadyLinked = false))
    }

    /**
     * INV-14 — `switchAccount()` is BOUND to the refused credential: the same
     * payload under 5 minutes, else a re-fetched credential that must name the
     * same identity (Play Games `playerId`, email, OIDC `sub`, passkey id),
     * aborting `credential_changed` otherwise. Called by the app OUTSIDE the
     * mutex (the link already returned), so it goes through [signInWith].
     */
    private suspend fun switchFromRefusedLink(
        refused: Credential,
        refusedAt: Long,
        refetch: (suspend () -> Credential)?,
    ): Result<SignInResult> {
        val cred = boundCredential(refused, refusedAt, refetch).getOrElse { return Result.failure(it) }
        return signInWith(cred)
    }

    private suspend fun boundCredential(refused: Credential, refusedAt: Long, refetch: (suspend () -> Credential)?): Result<Credential> {
        if (clock() - refusedAt < SWITCH_PAYLOAD_MAX_AGE_MS) return Result.success(refused)
        val again = refetch?.invoke()
            ?: return Result.failure(SendoraCloudAuthError.CredentialChanged(
                "The refused credential is older than 5 minutes; obtain it again natively and pass it to switchAccount(refetch)",
            ))
        if (!sameIdentity(refused, again)) {
            return Result.failure(SendoraCloudAuthError.CredentialChanged(
                "The re-fetched credential names a different identity than the one the player confirmed",
            ))
        }
        return Result.success(again)
    }

    /**
     * Client-side identity comparison for a re-fetched credential. Conservative:
     * when the two payloads cannot be compared (an authorization code, a Play
     * Games code with no `playerId`) they are NOT the same identity — the SDK
     * never signs the player into whatever the device now says.
     */
    private fun sameIdentity(a: Credential, b: Credential): Boolean = when {
        a is Credential.Password && b is Credential.Password -> a.email.equals(b.email, ignoreCase = true)
        a is Credential.EmailOtp && b is Credential.EmailOtp -> a.email.equals(b.email, ignoreCase = true)
        a is Credential.MagicLink && b is Credential.MagicLink -> a.token == b.token
        a is Credential.Mfa && b is Credential.Mfa -> a.challengeToken == b.challengeToken
        a is Credential.PlayGames && b is Credential.PlayGames -> a.playerId != null && a.playerId == b.playerId
        a is Credential.Passkey && b is Credential.Passkey -> a.assertion["id"] != null && a.assertion["id"] == b.assertion["id"]
        a is Credential.Social && b is Credential.Social -> {
            val subA = decodeJwtPayload(a.idToken)?.optString("sub", "")?.takeIf { it.isNotEmpty() }
            val subB = decodeJwtPayload(b.idToken)?.optString("sub", "")?.takeIf { it.isNotEmpty() }
            a.provider == b.provider && subA != null && subA == subB
        }
        else -> false
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELD GUESTS (§3.3 rows 29–32) — the three destructive/identity verbs
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Fold a held guest INTO the current identified account (`POST /merge`):
     * events, profiles, entities and push registrations move to this account,
     * the guest row is deleted server-side and `auth.user_merged` fires. This
     * is DESTRUCTIVE and irreversible, Sendora-side only (your own data keyed
     * on the guest's id is untouched), and OPTIONAL — an app whose backend does
     * not act on `auth.user_merged` MUST NOT call it. Identified sessions only.
     * `id` may be omitted only when exactly one guest is held
     * ([SendoraCloudAuthError.AmbiguousHeldGuest] otherwise). The held token is
     * refreshed first and the rotation persisted into its slot BEFORE the merge
     * (a spent parent inside the 60 s grace is repaired, liveness is proven).
     * Emits `UserUpdated(cause = MERGE)` then `GuestReleased(CLAIMED)`.
     */
    suspend fun claimHeldGuest(id: String? = null): Result<ClaimResult> = serialize {
        rejectIfWithheld()?.let { return@serialize Result.failure(it) }
        if (status() != AuthStatus.IDENTIFIED) {
            return@serialize Result.failure(SendoraCloudAuthError.Unauthorized(
                "claimHeldGuest() requires an identified session — the current account is the merge target",
            ))
        }
        val index = resolveHeldIndex(id).getOrElse { return@serialize Result.failure(it) }
        claimSlot(index)
    }

    /**
     * Sign back in as a held guest WITHOUT merging — the guest becomes the
     * current session again. From `SIGNED_OUT` or an identified account (whose
     * session is revoked fire-and-forget); from a GUEST the current guest is
     * held in turn (slot written first, so there is never a window with zero
     * handles to either). The slot's `project` recorded at hold must be this
     * build's project ([SendoraCloudAuthError.HeldGuestProjectMismatch], no
     * network); a guest the server reports gone is released and fails
     * `held_guest_gone`. Emits `SignedIn(cause = RESTORE)` then
     * `GuestReleased(RESTORED)`; re-register push on it. Queued in `UNKNOWN`;
     * rejects `SESSION_WITHHELD`.
     */
    suspend fun restoreHeldGuest(id: String? = null): Result<SendoraCloudAuthUser> {
        awaitSettledIfUnknown()
        return serialize {
            rejectIfWithheld()?.let { return@serialize Result.failure(it) }
            val index = resolveHeldIndex(id).getOrElse { return@serialize Result.failure(it) }
            when (val r = restoreSlot(index)) {
                is RestoreOutcome.Restored -> Result.success(r.user)
                is RestoreOutcome.Dead -> Result.failure(SendoraCloudAuthError.HeldGuestGone(
                    "The held guest is no longer available (${r.endReason})", r.endReason,
                ))
                is RestoreOutcome.Kept -> Result.failure(SendoraCloudAuthError.RestoreFailed(
                    "The held guest's token was refused without proof it is gone; the slot is kept — retry later", r.endReason,
                ))
                is RestoreOutcome.Mismatch -> Result.failure(SendoraCloudAuthError.HeldGuestProjectMismatch(
                    "The held guest belongs to project ${r.slotProject}, not ${r.expected}", r.slotProject, r.expected,
                ))
                is RestoreOutcome.Failed -> Result.failure(r.error)
            }
        }
    }

    /**
     * Delete a held guest for good (`POST /guest/discard` with the guest's own
     * refresh token — a REAL server delete: data, credentials, row,
     * `auth.user_deleted { reason: "guest_discarded" }`, no grace). The app is
     * the requester on behalf of its player; the SDK never calls this on its
     * own. A 404 (already gone) also releases the slot; a 5xx / network failure
     * keeps it (the guest is not gone). Emits `GuestReleased(DISCARDED)`.
     */
    suspend fun discardHeldGuest(id: String? = null): Result<Unit> = serialize {
        rejectIfWithheld()?.let { return@serialize Result.failure(it) }
        val index = resolveHeldIndex(id).getOrElse { return@serialize Result.failure(it) }
        discardSlot(index)
    }

    private suspend fun discardSlot(index: Int): Result<Unit> {
        val guest = heldSlots[index]?.parsed ?: return Result.failure(SendoraCloudAuthError.Unknown("Held guest not found", code = "HELD_GUEST_NOT_FOUND"))
        val response = client.post("/auth-service/guest/discard", mapOf("refreshToken" to guest.refreshToken))
            ?: return Result.failure(SendoraCloudAuthError.Network("discardHeldGuest failed (network error)"))
        val err = parseError(response)
        if (err != null && err.status != 404) return Result.failure(err)
        commit(AuthTx.Release(index, GuestReleasedReason.DISCARDED, endReason = null))
        return Result.success(Unit)
    }

    /**
     * ⚠ DEPRECATED — kept callable. Claims the held guest whose current OR
     * at-hold refresh token matches (the integrator-journalled token keeps
     * routing to the right slot after a rotation); a token no slot knows goes
     * to `POST /merge` raw, as before. Either way a DESTRUCTIVE claim (INV-8).
     */
    @Deprecated("Use claimHeldGuest(id) — the SDK journals a replaced guest itself (ADR-033).", ReplaceWith("claimHeldGuest(id)"))
    suspend fun merge(anonRefreshToken: String): Result<ClaimResult> = serialize {
        rejectIfWithheld()?.let { return@serialize Result.failure(it) }
        if (status() != AuthStatus.IDENTIFIED) {
            return@serialize Result.failure(SendoraCloudAuthError.Unauthorized("merge() requires an identified session"))
        }
        val index = heldSlots.indexOfFirst { it?.parsed?.let { g -> g.refreshToken == anonRefreshToken || g.tokenAtHold == anonRefreshToken } == true }
        if (index >= 0) return@serialize claimSlot(index)
        identityAttempt { expect -> mergeRaw(anonRefreshToken, expect) }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SIGN OUT / DELETE / WITHHELD DISCARD / RESET (§3.3 rows 14, 27, 28, 33)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Sign out — local-first (the one deliberate exception to proposal-then-CAS:
     * the user is logged out on device even if the revoke request hangs), then
     * a fire-and-forget `/token/revoke`. KEEPS held guests (a guest's refresh
     * token is its only credential — stranding it would be deletion by
     * assumption), keeps the event queue, rotates the analytics anonymous id.
     * In `WITHHELD` this is [discardWithheld]. Emits `SignedOut(USER)` when a
     * session was cleared; nothing when there was none.
     */
    suspend fun signOut() = guardedValue {
        mutex.withLock {
            when (val s = slot) {
                is AuthSlot.Withheld -> discardWithheldLocked(s)
                is AuthSlot.Session -> commit(AuthTx.Clear(
                    reason = AuthSignedOutReason.USER, expectRefresh = null, revokeToken = s.record.refreshToken,
                    effects = AuthWipeEffects(rotateDeviceId = true, clearQueue = false, clearUserId = true),
                    stampHeldNoAutoRestore = false,
                ))
                is AuthSlot.Limbo -> commit(AuthTx.Clear(
                    reason = AuthSignedOutReason.USER, expectRefresh = null, revokeToken = s.refreshToken,
                    effects = AuthWipeEffects(rotateDeviceId = true, clearQueue = false, clearUserId = true),
                    stampHeldNoAutoRestore = false,
                ))
                // Nothing to clear and nothing to report (INV-7); the shared-device
                // anon-id rotation an explicit sign-out always performed is kept.
                AuthSlot.Empty -> onAnonymousWipe(AuthWipeEffects(rotateDeviceId = true, clearQueue = false, clearUserId = true))
            }
        }
    }

    /**
     * Outcome of [deleteAccount]. [status] is `"purged"` (hard-deleted now,
     * grace = 0) or `"pending"` (deactivated + sessions revoked now, hard
     * delete scheduled at [scheduledPurgeAt]; cancellable by signing back in).
     * [heldGuests] (4.26.0) counts the guests still held on this device after
     * the call; [heldGuestDiscardFailures] names those `alsoDiscardHeldGuests`
     * could not delete (they stay held).
     */
    data class AccountDeletionResult(
        val status: String,
        val scheduledPurgeAt: String?,
        val graceDays: Int,
        val heldGuests: Int = 0,
        val heldGuestDiscardFailures: List<String> = emptyList(),
    )

    /**
     * Delete the signed-in user's account (Apple App Store Guideline 5.1.1(v)).
     * Resolves a FRESH access token first (a 401 from a stale token would
     * strand the user with an undeleted account), requires a CONFIRMED success
     * before clearing anything, then clears the session, rotates the anonymous
     * id, drops the queued events (s58.353) and emits `SignedOut(ACCOUNT_DELETED)`.
     *
     * ⚠ Held guests SURVIVE on the device and the server — deleting an account
     * never deletes a guest saved on this device unless you ask: with
     * [alsoDiscardHeldGuests] each held guest is discarded after the 2xx
     * (failures reported, those slots kept). By default they are only marked
     * so that the next `ensureSession()` mints a fresh guest instead of
     * reviving one (explicit [restoreHeldGuest] still works). Your privacy
     * copy must say so.
     */
    suspend fun deleteAccount(alsoDiscardHeldGuests: Boolean = false): Result<AccountDeletionResult> = serialize {
        rejectIfWithheld()?.let { return@serialize Result.failure(it) }
        val token = getAccessToken()
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val sentRefresh = getRefreshToken()
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
        commit(AuthTx.Clear(
            reason = AuthSignedOutReason.ACCOUNT_DELETED, expectRefresh = sentRefresh, revokeToken = null,
            effects = AuthWipeEffects(rotateDeviceId = true, clearQueue = true, clearUserId = true),
            stampHeldNoAutoRestore = true,
        ))
        val failures = mutableListOf<String>()
        if (alsoDiscardHeldGuests) {
            for (index in heldSlots.indices) {
                val guest = heldSlots[index]?.parsed ?: continue
                discardSlot(index).onFailure { failures += guest.userId }
            }
        }
        Result.success(AccountDeletionResult(
            status = data?.get("status") as? String ?: "pending",
            scheduledPurgeAt = data?.get("scheduledPurgeAt") as? String,
            graceDays = (data?.get("graceDays") as? Number)?.toInt() ?: 0,
            heldGuests = heldCount(),
            heldGuestDiscardFailures = failures,
        ))
    }

    /**
     * Leave `WITHHELD`: clear exactly the stored session's keys (the withheld
     * tokens, a `/token/revoke` fire-and-forget like `signOut()`), LOCAL ONLY —
     * never a server delete, never `/guest/discard`. Held guests, the event
     * queue and the analytics `user_id` are kept. Emits `SignedOut(USER)`.
     * Resolves `false` and does nothing when `status() != WITHHELD`.
     */
    suspend fun discardWithheld(): Result<Boolean> = serialize {
        val s = slot as? AuthSlot.Withheld ?: return@serialize Result.success(false)
        Result.success(discardWithheldLocked(s))
    }

    private suspend fun discardWithheldLocked(s: AuthSlot.Withheld): Boolean = commit(AuthTx.Clear(
        reason = AuthSignedOutReason.USER, expectRefresh = s.refreshToken, revokeToken = s.refreshToken,
        effects = AuthWipeEffects(rotateDeviceId = false, clearQueue = false, clearUserId = false),
        stampHeldNoAutoRestore = false,
    ))

    /**
     * The machine's RESET transaction (fixture row `reset.keeps_held`): the
     * sign-out row + clear the event queue; in `WITHHELD` the withheld discard +
     * queue clear. KEEPS held guests unless [includeHeldGuests], which releases
     * every slot LOCALLY (`GuestReleased(RESET)` each) with no server delete.
     *
     * ⚠ NOT wired to `SendoraCloud.reset()` on Android. 4.25.0's `reset()` never
     * signed out (it only forgets the analytics identity), and the wave-1
     * lockstep ruling is that a MINOR must not widen it, so the public call
     * keeps its 4.25.0 semantics. This transaction is the conformance replay's
     * subject for the RESET row and the single place a future auth-clearing
     * reset must go through.
     */
    internal suspend fun resetSession(includeHeldGuests: Boolean) {
        mutex.withLock {
            val effects = AuthWipeEffects(rotateDeviceId = true, clearQueue = true, clearUserId = true)
            when (val s = slot) {
                is AuthSlot.Withheld -> commit(AuthTx.Clear(AuthSignedOutReason.USER, s.refreshToken, s.refreshToken, effects, stampHeldNoAutoRestore = false))
                is AuthSlot.Session -> commit(AuthTx.Clear(AuthSignedOutReason.USER, null, s.record.refreshToken, effects, stampHeldNoAutoRestore = false))
                is AuthSlot.Limbo -> commit(AuthTx.Clear(AuthSignedOutReason.USER, null, s.refreshToken, effects, stampHeldNoAutoRestore = false))
                AuthSlot.Empty -> onAnonymousWipe(effects)
            }
            if (includeHeldGuests) {
                for (index in heldSlots.indices) {
                    if (heldSlots[index] != null) commit(AuthTx.Release(index, GuestReleasedReason.RESET, endReason = null))
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SESSION VERBS (not transitions; reject in WITHHELD)
    // ═══════════════════════════════════════════════════════════════════════

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
        rejectIfWithheld()?.let { return@guardedResult Result.failure(it) }
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/email/verify/resend", emptyMap(), headers)
        parseError(response)?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    // --- MFA enrollment management (Bearer-authenticated) ---

    data class MfaEnrollment(val secret: String, val otpauthUrl: String, val recoveryCodes: List<String>)

    suspend fun enrollMfa(): Result<MfaEnrollment> = guardedResult {
        rejectIfWithheld()?.let { return@guardedResult Result.failure(it) }
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
        rejectIfWithheld()?.let { return@guardedResult Result.failure(it) }
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/mfa/enroll/confirm", mapOf("code" to code), headers)
        @Suppress("UNCHECKED_CAST")
        val confirmed = (response?.get("data") as? Map<String, Any?>)?.get("confirmed") as? Boolean ?: false
        Result.success(confirmed)
    }

    /**
     * Disable MFA.
     *
     * ⚠ STEP-UP gated (s58.319): a token whose `auth_time` is stale is refused
     * with 403 `RECENT_AUTH_REQUIRED` ([SendoraCloudAuthErrorKind.RECENT_AUTH_REQUIRED]).
     *
     * ⚠ The response used to be DISCARDED, and `ApiClient` is documented "never
     * throws — errors log and the call returns null", so that refusal, a
     * timeout, and an open circuit breaker all reported MFA as off while TOTP
     * stayed enrolled server-side.
     */
    suspend fun disableMfa(): Result<Unit> = guardedResult {
        rejectIfWithheld()?.let { return@guardedResult Result.failure(it) }
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.post("/auth-service/mfa/disable", emptyMap(), headers)
        parseError(response)?.let { return@guardedResult Result.failure(it) }
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
        rejectIfWithheld()?.let { throw it }
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

    /**
     * Revoke one of the caller's own sessions ("sign out that device").
     *
     * ⚠ Widened `Unit` -> `Result<Unit>` in 4.21.0 (source-compatible). It
     * previously discarded the response entirely: a "sign out this device"
     * button that reports success on a failure is the one place a user acts
     * on the claim and then stops worrying about a device they no longer control.
     */
    suspend fun revokeSession(sessionId: String): Result<Unit> = guardedResult {
        rejectIfWithheld()?.let { return@guardedResult Result.failure(it) }
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.delete("/auth-service/sessions/me/$sessionId", headers)
        parseError(response)?.let { return@guardedResult Result.failure(it) }
        Result.success(Unit)
    }

    /** Revoke every session for the caller. Same 4.21.0 change as [revokeSession]. */
    suspend fun revokeAllSessions(): Result<Unit> = guardedResult {
        rejectIfWithheld()?.let { return@guardedResult Result.failure(it) }
        val headers = bearerHeaders()
            ?: return@guardedResult Result.failure(SendoraCloudAuthError.Unauthorized("Not signed in"))
        val response = client.delete("/auth-service/sessions/me", headers)
        parseError(response)?.let { return@guardedResult Result.failure(it) }
        Result.success(Unit)
    }

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
     * "Connected: Play Games · Google" UI. Bearer-authenticated network read
     * that resolves a fresh access token first.
     */
    suspend fun listLinkedIdentities(): Result<LinkedIdentitiesResult> = serialize {
        rejectIfWithheld()?.let { return@serialize Result.failure(it) }
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

    /**
     * Remove one linked provider from the signed-in account — what a
     * "Disconnect" button beside each entry on a Connected Accounts screen
     * calls. ⚠ The server REFUSES to remove the last way into the account
     * (`LAST_CREDENTIAL`); prefer disabling the tap when
     * `identities.size + (if (hasPassword) 1 else 0) <= 1`. An absent provider
     * is NOT reported as a successful removal. Emits `UserUpdated(UNLINK)` when
     * the server returned the updated user.
     */
    suspend fun unlink(provider: String): Result<UnlinkResult> = serialize {
        rejectIfWithheld()?.let { return@serialize Result.failure(it) }
        val token = getAccessToken()
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unauthorized("Sign in before unlinking an identity"))
        val headers = mapOf("Authorization" to "Bearer $token")
        val escaped = URLEncoder.encode(provider, "UTF-8")
        val response = client.delete("/auth-service/me/identities/$escaped", headers)
            ?: return@serialize Result.failure(SendoraCloudAuthError.Network("unlink failed (network error)"))
        val err = parseError(response)
        if (err != null) return@serialize Result.failure(err)
        @Suppress("UNCHECKED_CAST")
        val data = response["data"] as? Map<String, Any?>
            ?: return@serialize Result.failure(SendoraCloudAuthError.Unknown("Malformed unlink response"))
        Result.success(
            UnlinkResult(
                provider = data["provider"] as? String ?: provider,
                removed = (data["removed"] as? Number)?.toInt() ?: 0,
                remaining = (data["remaining"] as? Number)?.toInt() ?: 0,
            ),
        )
    }

    private fun bearerHeaders(): Map<String, String>? {
        val token = accessToken ?: return null
        return mapOf("Authorization" to "Bearer $token")
    }

    internal val passkeys: SendoraCloudPasskeys by lazy {
        SendoraCloudPasskeys(
            client = client,
            secureAvailable = { storage.isSecureAvailable },
            bearerProvider = { if (slot is AuthSlot.Withheld) null else getAccessToken() },
            installSession = { payload ->
                mutex.withLock {
                    // A passkey sign-in is a SWITCH through the commit funnel: the
                    // minted session is validated, a current guest is HELD, and
                    // only then is the new session installed.
                    if (!storage.isSecureAvailable || slot is AuthSlot.Withheld) null
                    else identityAttempt { expect ->
                        val response = mapOf("data" to payload)
                        val record = parseRecord(response, clock()) ?: return@identityAttempt null
                        val outcome = commitIdentity(AuthTx.Install(
                            record = record, reason = InstallReason.SIGN_IN, expectIdentity = expect,
                            holdPreviousGuest = true, revokePreviousIdentified = true,
                            emit = Emit.SignedIn(AuthSignedInCause.SIGN_IN),
                        ))
                        if (outcome is CommitOutcome.Applied) {
                            recordLegacyResponseSignals(payload, record.user)
                            record.user
                        } else null
                    }
                }
            },
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internals — attempts, queueing, held-slot helpers, the refresh paths
    // ═══════════════════════════════════════════════════════════════════════

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

    /** The `withheld | <verb>` row: a typed refusal, no network, no write. */
    private fun rejectIfWithheld(): SendoraCloudAuthError? =
        if (slot is AuthSlot.Withheld) SendoraCloudAuthError.SessionWithheld(
            "The stored session belongs to another project and is withheld; call discardWithheld() or relaunch with the matching expectedProjectId",
        ) else null

    /**
     * INV-5: a session-installing verb in `UNKNOWN` is QUEUED until the single
     * gap-fill refresh settles the status — it never executes its network call
     * over an unsettled record. Runs OUTSIDE `mutex` so a waiting verb never
     * blocks `signOut()`. Offline, the proactive cron keeps retrying the
     * refresh and completes the waiters when it lands.
     */
    private suspend fun awaitSettledIfUnknown() {
        while (hydrated && slot is AuthSlot.Limbo) {
            refreshAccessToken(staleToken = STALE_NONE)
            if (slot !is AuthSlot.Limbo) return
            val waiter = CompletableDeferred<Unit>()
            synchronized(settleWaiters) {
                if (slot !is AuthSlot.Limbo) return
                settleWaiters += waiter
            }
            waiter.await()
        }
    }

    private fun notifySettledIfNeeded() {
        if (slot is AuthSlot.Limbo) return
        val waiters = synchronized(settleWaiters) { settleWaiters.toList().also { settleWaiters.clear() } }
        waiters.forEach { it.complete(Unit) }
    }

    /** The identity CAS key (INV-2): the `sid` family when the token carries one, else the refresh token itself. */
    private fun identityKey(): String? = when (val s = slot) {
        is AuthSlot.Session -> s.record.sid ?: s.record.refreshToken
        is AuthSlot.Limbo -> s.refreshToken
        is AuthSlot.Withheld -> "withheld:" + s.refreshToken
        AuthSlot.Empty -> null
    }

    /**
     * An identity-changing attempt (§3.3 scheduling rules): awaits any in-flight
     * refresh at START (so the request is built against the post-rotation
     * session), pauses the proactive cron for its duration, and hands the block
     * the identity snapshot its result will be CAS'd against at commit.
     */
    private suspend fun <T> identityAttempt(block: suspend (expect: String?) -> T): T {
        refreshMutex.withLock { }
        identityAttemptPending = true
        try {
            return block(identityKey())
        } finally {
            identityAttemptPending = false
        }
    }

    /** An identity commit awaits any refresh in flight at COMMIT time too, and excludes one while it runs. */
    private suspend fun commitIdentity(tx: AuthTx.Install): CommitOutcome = refreshMutex.withLock { commit(tx) }

    private suspend fun commitIdentityUser(tx: AuthTx.UpdateUser): Boolean = refreshMutex.withLock { commit(tx) }

    private fun heldCount(): Int = heldSlots.count { it != null }

    /** ADR-033 §3.2's T = |held| + (current anonymous ? 1 : 0) — the quantity bounded by K at MINT. */
    private fun totalGuests(): Int = heldCount() + if (currentUser?.isAnonymous == true) 1 else 0

    private fun heldLimitError() = SendoraCloudAuthError.HeldGuestLimit(
        "All $HELD_CAPACITY held-guest slots are occupied (or none is eligible) — restoreHeldGuest(id) or discardHeldGuest(id) first",
    )

    /** `id` may be omitted ONLY when exactly one guest is held (§3.5 — the dialog-to-tap TOCTOU). */
    private fun resolveHeldIndex(id: String?): Result<Int> {
        val occupied = heldSlots.indices.filter { heldSlots[it]?.parsed != null }
        if (id == null) {
            return when (occupied.size) {
                0 -> Result.failure(SendoraCloudAuthError.Unknown("No held guest on this device", code = "HELD_GUEST_NOT_FOUND"))
                1 -> Result.success(occupied.single())
                else -> Result.failure(SendoraCloudAuthError.AmbiguousHeldGuest(
                    "${occupied.size} guests are held on this device — pass the userId of the one you mean",
                ))
            }
        }
        val index = occupied.firstOrNull { heldSlots[it]?.parsed?.userId == id }
            ?: return Result.failure(SendoraCloudAuthError.Unknown("No held guest with id $id", code = "HELD_GUEST_NOT_FOUND"))
        return Result.success(index)
    }

    /** Auto-restore eligibility (§3.3): `autoRestore` set and the slot's project not mismatching this build's. */
    private fun eligibleHeldIndicesNewestFirst(): List<Int> {
        val expected = machine.expectedProjectId ?: machine.projectId
        return heldSlots.indices
            .filter { i ->
                val g = heldSlots[i]?.parsed ?: return@filter false
                g.autoRestore && (g.project == null || expected == null || g.project == expected)
            }
            .sortedByDescending { heldSlots[it]!!.parsed!!.heldAt }
    }

    private sealed class RestoreOutcome {
        data class Restored(val user: SendoraCloudAuthUser) : RestoreOutcome()
        data class Dead(val endReason: String?) : RestoreOutcome()
        data class Kept(val endReason: String?) : RestoreOutcome()
        data class Mismatch(val slotProject: String?, val expected: String?) : RestoreOutcome()
        data class Failed(val error: SendoraCloudAuthError) : RestoreOutcome()
    }

    /**
     * The RESTORE rows (30–31). Project check FIRST (client-side, no network);
     * `refreshHeld()` → ProjectGuard on the RESPONSE; install the held record as
     * current (holding a current guest / revoking a current identified account)
     * BEFORE removing the slot — never a window with zero handles to a guest.
     * Both paths (explicit restore and the MINT auto-restore) emit
     * `SignedIn(RESTORE)` then `GuestReleased(RESTORED)` — install, then release.
     */
    private suspend fun restoreSlot(index: Int): RestoreOutcome {
        val guest = heldSlots[index]?.parsed
            ?: return RestoreOutcome.Failed(SendoraCloudAuthError.Unknown("Held guest not found", code = "HELD_GUEST_NOT_FOUND"))
        val expected = machine.expectedProjectId ?: machine.projectId
        if (guest.project != null && expected != null && guest.project != expected) {
            return RestoreOutcome.Mismatch(guest.project, expected)
        }
        return identityAttempt { expect ->
            when (val r = refreshHeld(index)) {
                is HeldRefresh.Dead -> RestoreOutcome.Dead(r.endReason)
                is HeldRefresh.Kept -> RestoreOutcome.Kept(r.endReason)
                is HeldRefresh.Failed -> RestoreOutcome.Failed(r.error)
                is HeldRefresh.Rotated -> {
                    val record = r.record
                    if (verdictFor(record) == ProjectVerdict.MISMATCH) {
                        // Record the claim the response just revealed (the slot had
                        // `null`); the rotation is already persisted. Install nothing.
                        commit(AuthTx.RotateHeld(index, sent = record.refreshToken, newRefresh = record.refreshToken, project = record.projectClaim, recordProject = true))
                        return@identityAttempt RestoreOutcome.Mismatch(record.projectClaim, machine.expectedProjectId)
                    }
                    if (slot is AuthSlot.Session && (slot as AuthSlot.Session).record.user.isAnonymous && freeHeldIndex(excluding = index) == null) {
                        return@identityAttempt RestoreOutcome.Failed(heldLimitError())
                    }
                    val outcome = commitIdentity(AuthTx.Install(
                        record = record, reason = InstallReason.RESTORE, expectIdentity = expect,
                        holdPreviousGuest = true, revokePreviousIdentified = true,
                        emit = Emit.SignedIn(AuthSignedInCause.RESTORE),
                    ))
                    if (outcome !is CommitOutcome.Applied) return@identityAttempt RestoreOutcome.Failed(outcome.asError(record))
                    // Install first, THEN release the slot — on both paths (explicit
                    // restore and the MINT auto-restore), so the events read
                    // `SignedIn(RESTORE)` then `GuestReleased(RESTORED)` (fixture rows
                    // `restore.held_guest` + `mint.auto_restore`).
                    commit(AuthTx.Release(index, GuestReleasedReason.RESTORED, endReason = null))
                    RestoreOutcome.Restored(record.user)
                }
            }
        }
    }

    /** The CLAIM row (29): refreshHeld → persist into the slot → `POST /merge` → install the target pair → release. */
    private suspend fun claimSlot(index: Int): Result<ClaimResult> = identityAttempt { expect ->
        when (val r = refreshHeld(index)) {
            is HeldRefresh.Dead -> Result.failure(SendoraCloudAuthError.HeldGuestGone("The held guest is no longer available (${r.endReason})", r.endReason))
            is HeldRefresh.Kept -> Result.failure(SendoraCloudAuthError.RestoreFailed("The held guest's token was refused without proof it is gone; the slot is kept — retry later", r.endReason))
            is HeldRefresh.Failed -> Result.failure(r.error)
            is HeldRefresh.Rotated -> mergeRaw(r.record.refreshToken, expect, releaseIndex = index)
        }
    }

    /** `POST /merge { anonRefreshToken, refreshToken }` → install the rotated TARGET pair (same user), `UserUpdated(MERGE)`. */
    private suspend fun mergeRaw(anonRefreshToken: String, expect: String?, releaseIndex: Int? = null): Result<ClaimResult> {
        val current = slot as? AuthSlot.Session
            ?: return Result.failure(SendoraCloudAuthError.Unauthorized("merge requires an identified session"))
        val response = client.post("/auth-service/merge", mapOf("anonRefreshToken" to anonRefreshToken, "refreshToken" to current.record.refreshToken))
        parseError(response)?.let { return Result.failure(it) }
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?>
            ?: return Result.failure(SendoraCloudAuthError.Unknown("Malformed merge response"))
        @Suppress("UNCHECKED_CAST")
        val tokens = data["tokens"] as? Map<String, Any?>
            ?: return Result.failure(SendoraCloudAuthError.Unknown("Malformed merge response"))
        val trio = readTokenTrio(tokens) ?: return Result.failure(SendoraCloudAuthError.Unknown("Malformed merge response"))
        val record = AuthRecord(current.record.user, trio.first, trio.second, clock() + trio.third * 1000L)
        val outcome = commitIdentity(AuthTx.Install(
            record = record, reason = InstallReason.CLAIM, expectIdentity = expect,
            holdPreviousGuest = false, revokePreviousIdentified = false,
            emit = Emit.UserUpdated(AuthUserUpdatedCause.MERGE),
        ))
        if (outcome !is CommitOutcome.Applied) return Result.failure(outcome.asError(record))
        releaseIndex?.let { commit(AuthTx.Release(it, GuestReleasedReason.CLAIMED, endReason = null)) }
        fun n(k: String) = (data[k] as? Number)?.toInt() ?: 0
        return Result.success(ClaimResult(record.user, MergeStats(
            mergedUserId = data["mergedUserId"] as? String ?: record.user.id,
            deletedAnonymousId = data["deletedAnonymousId"] as? String ?: "",
            eventsReassigned = n("eventsReassigned"), profilesReassigned = n("profilesReassigned"),
            profilesDropped = n("profilesDropped"), entitiesReassigned = n("entitiesReassigned"),
            entitiesDropped = n("entitiesDropped"), pushTokensReassigned = n("pushTokensReassigned"),
        )))
    }

    private sealed class HeldRefresh {
        data class Rotated(val record: AuthRecord) : HeldRefresh()
        data class Dead(val endReason: String?) : HeldRefresh()
        data class Kept(val endReason: String?) : HeldRefresh()
        data class Failed(val error: SendoraCloudAuthError) : HeldRefresh()
    }

    /**
     * Present a HELD token to `/token/refresh` (the only time a held token is
     * ever presented — the proactive cron never refreshes a held guest). A
     * rotation is persisted INTO ITS SLOT by sent-token CAS before anything
     * else happens (row 22). A dead verdict releases the slot ONLY for
     * `endReason` ∈ deleted|revoked|expired (row 25); `reuse` or an absent
     * reason KEEPS it.
     */
    private suspend fun refreshHeld(index: Int): HeldRefresh {
        val guest = heldSlots[index]?.parsed
            ?: return HeldRefresh.Failed(SendoraCloudAuthError.Unknown("Held guest not found", code = "HELD_GUEST_NOT_FOUND"))
        val sent = guest.refreshToken
        val response = client.post("/auth-service/token/refresh", mapOf("refreshToken" to sent))
            ?: return HeldRefresh.Failed(SendoraCloudAuthError.Network("Could not reach the server to refresh the held guest"))
        if (response["success"] == false) {
            val error = objectField(response["error"])
            val code = error?.get("code") as? String
            val endReason = objectField(error?.get("details"))?.get("endReason") as? String
            if (code != null && isDeadRefreshError(code)) {
                return if (endReason != null && endReason in AuthMachineSets.RELEASE_HELD_ON_END_REASONS) {
                    commit(AuthTx.Release(index, GuestReleasedReason.DEAD, endReason))
                    HeldRefresh.Dead(endReason)
                } else {
                    HeldRefresh.Kept(endReason)
                }
            }
            return HeldRefresh.Failed(parseError(response) ?: SendoraCloudAuthError.Unknown("Refresh failed"))
        }
        @Suppress("UNCHECKED_CAST")
        val data = response["data"] as? Map<String, Any?>
            ?: return HeldRefresh.Failed(SendoraCloudAuthError.Unknown("Malformed refresh response"))
        @Suppress("UNCHECKED_CAST")
        val tokenFields = (data["tokens"] as? Map<String, Any?>) ?: data // nested since s58.76 (see refreshAccessToken)
        val trio = readTokenTrio(tokenFields) ?: return HeldRefresh.Failed(SendoraCloudAuthError.Unknown("Malformed refresh response"))
        @Suppress("UNCHECKED_CAST")
        val user = (data["user"] as? Map<String, Any?>)?.let(AuthCodecs::userFromMap)
            ?: return HeldRefresh.Failed(SendoraCloudAuthError.Unknown("Refresh response carries no user"))
        // ⚠ IDENTITY TRIPWIRE (s58.360, parity RN 1.41.2 / web 3.24.2 / iOS 5.4.2). The
        // refresh must come back for the held GUEST. Before the server fix
        // `/token/refresh` preferred the `sd_rt` cookie over the body; wherever a cookie
        // jar replayed the signed-in ACCOUNT's cookie the 200 was the account's, and
        // committing it overwrote the guest's only token. (This SDK's HttpURLConnection
        // sends cookies only if the host app installed a default CookieHandler.)
        // Refuse BEFORE the slot write: nothing written, nothing installed, slot kept.
        if (user.id.isNotEmpty() && user.id != guest.userId) {
            return HeldRefresh.Failed(
                SendoraCloudAuthError.Unknown(
                    "The held guest's refresh was answered for a different account; nothing was changed",
                    code = "HELD_GUEST_IDENTITY_MISMATCH",
                ),
            )
        }
        val record = AuthRecord(user, trio.first, trio.second, clock() + trio.third * 1000L)
        if (!commit(AuthTx.RotateHeld(index, sent = sent, newRefresh = trio.second, project = null, recordProject = false))) {
            return HeldRefresh.Failed(SendoraCloudAuthError.Superseded("The held slot changed while its token was being refreshed"))
        }
        return HeldRefresh.Rotated(record)
    }

    /**
     * Hot-path token refresh for the CURRENT session, single-flight under
     * `refreshMutex`. The ONE background path that can end a session, and only
     * on the per-user verdict `INVALID_REFRESH_TOKEN` (INV-6) — a 429, 5xx,
     * timeout or generic 401 (what the API-key middleware returns for a rotated
     * `pk_` key) never clears anything. The rotation is applied by sent-token
     * CAS (row 20) and judged by the ProjectGuard before install (row 21);
     * from `UNKNOWN` this is the gap-fill that settles the status.
     */
    private suspend fun refreshAccessToken(staleToken: String? = null): String? = refreshMutex.withLock {
        val nowMs = clock()
        val (cached, expiresAt) = currentTokenAndDeadline()
        val refresh = when (val s = slot) {
            is AuthSlot.Session -> s.record.refreshToken
            is AuthSlot.Limbo -> s.refreshToken
            else -> return@withLock null
        }
        // Re-check after acquiring the lock; another caller may have already
        // refreshed. Same combined guard as the fast path — but never for an
        // UNKNOWN record (its token is not servable until the gap-fill settles
        // it) and never the very token the caller asked to replace
        // ([staleToken]: a forced refresh or the proactive anticipation, both of
        // which hold a token that still passes the guard).
        if (slot is AuthSlot.Session && canServeToken(cached, expiresAt, nowMs) && (staleToken == null || cached != staleToken)) {
            return@withLock cached
        }
        val response = client.post("/auth-service/token/refresh", mapOf("refreshToken" to refresh))
        if (response != null && response["success"] == false) {
            val error = objectField(response["error"])
            val code = error?.get("code") as? String
            if (code != null && isDeadRefreshError(code)) {
                // ADR-033 B11: the server's own end reason rides in `SignedOut.endReason`;
                // `reason` is ALWAYS SESSION_EXPIRED (4.26.1 — see AuthSignedOutReason).
                // The Clear CAS'es on the token the server rejected — a sign-in or
                // signOut that landed meanwhile is not the session declared dead.
                val endReason = objectField(error?.get("details"))?.get("endReason") as? String
                commit(AuthTx.Clear(
                    reason = AuthSignedOutReason.SESSION_EXPIRED, expectRefresh = refresh, revokeToken = null,
                    endReason = endReason,
                    effects = AuthWipeEffects(rotateDeviceId = false, clearQueue = false, clearUserId = true),
                    stampHeldNoAutoRestore = false,
                ))
            }
            return@withLock null
        }
        @Suppress("UNCHECKED_CAST")
        val data = response?.get("data") as? Map<String, Any?> ?: return@withLock null
        // The rotated trio lives under `data.tokens` (alongside `data.user`),
        // matching every other auth response. It was FLAT before s58.76, and
        // reading the wrong level does not fail loudly — it just never
        // refreshes, so the session dies at access-token expiry. Accept both.
        @Suppress("UNCHECKED_CAST")
        val tokenFields = (data["tokens"] as? Map<String, Any?>) ?: data
        val trio = readTokenTrio(tokenFields) ?: return@withLock null
        @Suppress("UNCHECKED_CAST")
        val user = (data["user"] as? Map<String, Any?>)?.let(AuthCodecs::userFromMap)
        val outcome = commit(AuthTx.Rotate(sent = refresh, accessToken = trio.first, refreshToken = trio.second, expiresAt = nowMs + trio.third * 1000L, user = user))
        if (outcome == RotateOutcome.APPLIED) trio.first else null
    }

    /** The proactive tick (60 s + foreground): repair, anticipate, or gap-fill. Paused during an identity attempt. */
    private suspend fun tickProactive() {
        if (identityAttemptPending) return
        val nowMs = clock()
        when (val s = slot) {
            is AuthSlot.Limbo -> { refreshAndReconcile(nowMs); return }
            is AuthSlot.Session -> {
                val expMs = s.record.expiresAt
                if (expMs <= 0L) return
                // Repair, not just anticipate: a tracked deadline left stale by a
                // backwards clock step reads as "an hour of life left" and the
                // anticipation below never fires. The combined guard sees it.
                if (!canServeToken(s.record.accessToken, expMs, nowMs)) {
                    refreshAndReconcile(nowMs)
                    return
                }
                val remainingMs = expMs - nowMs
                if (remainingMs <= 0L) return
                val guessOriginalMs = maxOf(remainingMs, 5L * 60_000L)
                val jitter = Random.nextLong(-30_000L, 30_000L)
                val fireWhenRemainingMs = (guessOriginalMs * 0.2).toLong() + jitter
                if (remainingMs <= fireWhenRemainingMs) refreshAccessToken(staleToken = s.record.accessToken)
            }
            else -> return
        }
    }

    // ─── parsing ───────────────────────────────────────────────────────────

    /** `(accessToken, refreshToken, expiresIn seconds)` or `null` when any is missing/empty. */
    private fun readTokenTrio(tokens: Map<String, Any?>): Triple<String, String, Long>? {
        val accessToken = tokens["accessToken"] as? String
        val refreshToken = tokens["refreshToken"] as? String
        val expiresIn = (tokens["expiresIn"] as? Number)?.toLong()
        if (accessToken.isNullOrEmpty() || refreshToken.isNullOrEmpty() || expiresIn == null || expiresIn <= 0) return null
        return Triple(accessToken, refreshToken, expiresIn)
    }

    /** A full session record off a `{ data: { user, tokens } }` envelope — validated non-empty before anything is installed. */
    @Suppress("UNCHECKED_CAST")
    private fun parseRecord(response: Map<String, Any?>?, nowMs: Long): AuthRecord? {
        val data = response?.get("data") as? Map<String, Any?> ?: return null
        val userMap = data["user"] as? Map<String, Any?> ?: return null
        val tokensMap = data["tokens"] as? Map<String, Any?> ?: return null
        val user = AuthCodecs.userFromMap(userMap) ?: return null
        val trio = readTokenTrio(tokensMap) ?: return null
        return AuthRecord(user, trio.first, trio.second, nowMs + trio.third * 1000L)
    }

    /** The legacy response signals a 4.26.0 request never causes but a listener may still be registered for. */
    private fun recordLegacyResponseSignals(data: Map<String, Any?>, user: SendoraCloudAuthUser) {
        val retiredAnonUserId = data["retiredAnonUserId"] as? String
        if (!retiredAnonUserId.isNullOrEmpty()) {
            fireDeviceTakeover(retiredAnonUserId, user.id)
            emitAuthState(AuthStateChange.DeviceTakeover(user, retiredAnonUserId))
        }
        // s58.278 — record the guest-account outcome ONLY when the server states
        // it; an older backend leaves the previous value untouched rather than
        // asserting "nothing was retired".
        AnonRetirementOutcome.fromWire(data["anonRetirement"] as? String)
            ?.let { lastAnonRetirement = it }
        if (data["reactivatedFromDeletion"] as? Boolean == true) {
            fireDeletionCancelled(user.id)
            emitAuthState(AuthStateChange.DeletionCancelled(user))
        }
    }

    /** Canonical UUID validator (a tampered `retiredAnonUserId` must not reach a path-interpolating listener). */
    private fun isCanonicalUuid(s: String): Boolean {
        return try {
            java.util.UUID.fromString(s).toString().equals(s, ignoreCase = true)
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    /**
     * ONLY the specific code (`DEAD_CODES` in packages/shared). `UNAUTHORIZED` /
     * `HTTP_401` used to be accepted as a catch-all, but a 401 on this route is
     * NOT proof the refresh token is dead: the API-key middleware returns the
     * same generic 401 for a rotated publishable key. Rotating a `pk_` key would
     * therefore have wiped every install's guest at once.
     */
    private fun isDeadRefreshError(code: String): Boolean {
        return code in AuthMachineSets.DEAD_CODES
    }

    /** Read a nested object off a response envelope (either a Map or an `org.json` object). */
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
        // response the backend gave no `code` for still classify.
        val status = (error?.get("status") as? Number)?.toInt()
        val details = objectField(error?.get("details"))
        return when (code) {
            "NOT_ANONYMOUS" -> SendoraCloudAuthError.AlreadyIdentified(message, code, status)
            "CREDENTIAL_IN_USE" -> SendoraCloudAuthError.CredentialInUse(
                message, code, status, details?.get("provider") as? String, LinkCollision.fromWire(details?.get("collision") as? String),
            )
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

    private fun newMintKey(): String {
        val bytes = ByteArray(24)
        SecureRandom().nextBytes(bytes)
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * The verdict for a record about to be installed (INV-15): the JWT claim,
     * falling back to the B17 `user.project` field when the token says nothing.
     */
    private fun verdictFor(record: AuthRecord): ProjectVerdict {
        val expected = machine.expectedProjectId ?: return ProjectVerdict.MATCH
        val fromToken = projectVerdict(expected, record.accessToken)
        if (fromToken != ProjectVerdict.UNKNOWN) return fromToken
        if (!record.user.projectKnown) return ProjectVerdict.UNKNOWN
        val p = record.user.project ?: return ProjectVerdict.MISMATCH
        return if (p == expected) ProjectVerdict.MATCH else ProjectVerdict.MISMATCH
    }

    private fun actualProjectOf(record: AuthRecord): String? =
        record.projectClaim ?: if (record.projectClaimPresent) null else record.user.project

    /**
     * A new hold's `heldAt`: strictly greater than every held slot's
     * (`max(now, newest + 1)`). Two holds in the same millisecond (or a clock
     * stepped backwards) would otherwise tie, and "newest" — the `heldGuests()`
     * order and the auto-restore pick — would be undefined (web hit it as a
     * 1-in-4 flake). Lockstep rule, all four SDKs.
     */
    private fun nextHeldAt(): Long {
        val newest = heldSlots.mapNotNull { it?.parsed?.heldAt }.maxOrNull()
        return if (newest == null) clock() else maxOf(clock(), newest + 1)
    }

    private fun freeHeldIndex(excluding: Int? = null): Int? =
        heldSlots.indices.firstOrNull { heldSlots[it] == null && it != excluding }

    // ═══════════════════════════════════════════════════════════════════════
    // HYDRATE (§3.3 rows 1–4, 13; INV-9) — zero network, runs in the constructor
    // ═══════════════════════════════════════════════════════════════════════

    private fun hydrate() {
        // Held slots first: fixed keys, each KEPT when unparseable (P11).
        for (i in heldSlots.indices) {
            val raw = storage.secureGet(AuthKeys.HELD_SLOT_KEYS[i])
            heldSlots[i] = raw?.let { HeldSlot(it, HeldGuest.fromJson(it)) }
        }
        // Read-first: `auth_session`; else the four frozen keys (write-forward on a coherent install).
        //
        // ⚠ DOWNGRADE CYCLE. A 4.25.0 does not know `auth_session`: its signOut() /
        // deleteAccount() clear only the four frozen keys, so after
        // 4.26 → 4.25 → signOut → 4.26 the record SURVIVES and, trusted blindly,
        // would reinstall the account the user signed out of (or deleted). The
        // record is trusted ONLY when its refresh token equals the frozen refresh
        // key — every install writes the frozen keys FIRST, so a crash can leave
        // "frozen without record" (write-forward repairs it) but never "record
        // without frozen". A record with no matching frozen counterpart (absent,
        // different, or unparseable) is a leftover: cleared silently — no event,
        // no network — and the frozen keys are the truth.
        val frozenRefresh = storage.secureGet(AuthKeys.REFRESH)
        var sessionJson = storage.secureGet(AuthKeys.SESSION)
        var session = sessionJson?.let { AuthCodecs.sessionFromJson(it) }
        if (sessionJson != null && (session?.refreshToken.isNullOrEmpty() || session?.refreshToken != frozenRefresh)) {
            commit(AuthTx.DropLeftoverRecord)
            sessionJson = null
            session = null
        }
        val fromLegacy = session == null
        val legacyUserRaw = if (fromLegacy) storage.secureGet(AuthKeys.USER) else null
        val user = if (fromLegacy) legacyUserRaw?.let { AuthCodecs.userFromJson(it) } else session!!.user
        val access = if (fromLegacy) storage.secureGet(AuthKeys.ACCESS) else session!!.accessToken
        val refresh = if (fromLegacy) storage.secureGet(AuthKeys.REFRESH) else session!!.refreshToken
        val expiresAt = if (fromLegacy) storage.secureGetLong(AuthKeys.EXPIRES) else session!!.expiresAt
        heldReportPending = session?.heldReportPending ?: emptyList()

        if (refresh.isNullOrEmpty()) {
            // LIMBO_B: a user blob (or tokens) with no refresh token → clear the stale blob → SIGNED_OUT.
            if (legacyUserRaw != null || access != null || sessionJson != null) commit(AuthTx.ClearStaleBlob)
            slot = AuthSlot.Empty
        } else if (user == null || access.isNullOrEmpty()) {
            // LIMBO_A: the refresh token is independently valid and the ONLY thing
            // that can still recover the account — keep it, stay UNKNOWN, let the
            // single gap-fill refresh answer (never signed_out, never a mint).
            slot = AuthSlot.Limbo(refresh, access, expiresAt, user)
            cron.arm { tickProactive() }
        } else {
            commit(AuthTx.Install(
                record = AuthRecord(user, access, refresh, expiresAt),
                reason = InstallReason.HYDRATE,
                expectIdentity = null,
                holdPreviousGuest = false,
                revokePreviousIdentified = false,
                emit = Emit.None,
                writeForward = fromLegacy,
            ))
        }
        // INV-9 held-slot dedupe: a slot holding the CURRENT user is dropped (current wins).
        (slot as? AuthSlot.Session)?.record?.user?.id?.let { currentId ->
            for (i in heldSlots.indices) {
                if (heldSlots[i]?.parsed?.userId == currentId) commit(AuthTx.Release(i, GuestReleasedReason.RESET, endReason = null, silent = true))
            }
        }
        hydrated = true
        // B15: retry the pending hold reports (fire-and-forget), never from WITHHELD (zero writes there).
        if (slot !is AuthSlot.Withheld) {
            for (userId in heldReportPending) {
                heldSlots.firstOrNull { it?.parsed?.userId == userId }?.parsed?.let { reportHeld(it) }
            }
        }
    }

    private fun reportHeld(guest: HeldGuest) {
        background {
            val res = client.post("/auth-service/guest/held", mapOf("refreshToken" to guest.refreshToken))
            if (res?.get("success") == true) commit(AuthTx.HeldReported(guest.userId))
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // commit() — the ONLY writer (INV-1). Every storage write, every slot
    // assignment, every cron arm/disarm, every emission decision and every
    // parent-hook call below this line and nowhere else. §3.3's transaction
    // vocabulary, one `when` arm each.
    // ═══════════════════════════════════════════════════════════════════════

    private enum class InstallReason { MINT, SIGN_IN, UPGRADE, REFRESH, CLAIM, RESTORE, HYDRATE }

    private sealed class Emit {
        object None : Emit()
        data class SignedIn(val cause: AuthSignedInCause) : Emit()
        data class UserUpdated(val cause: AuthUserUpdatedCause) : Emit()
    }

    private sealed class AuthTx {
        class Install(
            val record: AuthRecord,
            val reason: InstallReason,
            /** The identity snapshot the result was derived from; `null` = "no session". Ignored for HYDRATE. */
            val expectIdentity: String?,
            val holdPreviousGuest: Boolean,
            val revokePreviousIdentified: Boolean,
            val emit: Emit,
            val writeForward: Boolean = false,
        ) : AuthTx()
        class Clear(
            val reason: AuthSignedOutReason,
            /** Token CAS: skip when the slot no longer holds this refresh token. `null` = local-first (sign-out). */
            val expectRefresh: String?,
            val revokeToken: String?,
            val effects: AuthWipeEffects,
            val stampHeldNoAutoRestore: Boolean,
            /** The server's `endReason` on a dead verdict (4.26.1) → `SignedOut.endReason`, never `reason`. */
            val endReason: String? = null,
        ) : AuthTx()
        class UpdateUser(val user: SendoraCloudAuthUser, val cause: AuthUserUpdatedCause, val expectIdentity: String?) : AuthTx()
        class Rotate(val sent: String, val accessToken: String, val refreshToken: String, val expiresAt: Long, val user: SendoraCloudAuthUser?) : AuthTx()
        class RotateHeld(val index: Int, val sent: String, val newRefresh: String, val project: String?, val recordProject: Boolean) : AuthTx()
        class Release(val index: Int, val reason: GuestReleasedReason, val endReason: String?, val silent: Boolean = false) : AuthTx()
        class HeldReported(val userId: String) : AuthTx()
        class MintKey(val key: String?) : AuthTx()
        object ClearStaleBlob : AuthTx()
        /** An `auth_session` record with no matching frozen refresh key (a 4.25.0 signed out / deleted under it). */
        object DropLeftoverRecord : AuthTx()
    }

    private sealed class CommitOutcome {
        data class Applied(val heldPrevious: Boolean) : CommitOutcome()
        object CasDropped : CommitOutcome()
        data class ProjectMismatch(val expected: String, val actual: String?) : CommitOutcome()
        object Withheld : CommitOutcome()
        object StayUnknown : CommitOutcome()
        object HeldLimit : CommitOutcome()

        fun asError(record: AuthRecord): SendoraCloudAuthError = when (this) {
            is Applied -> SendoraCloudAuthError.Unknown("applied")
            CasDropped -> SendoraCloudAuthError.Superseded("The session changed while the request was in flight; its result was dropped and its tokens revoked")
            is ProjectMismatch -> SendoraCloudAuthError.ProjectMismatch(
                "The server answered for project ${actual ?: "<org-wide>"} but this build expects $expected (user ${record.user.id})", expected, actual,
            )
            Withheld -> SendoraCloudAuthError.SessionWithheld("The session was withheld")
            StayUnknown -> SendoraCloudAuthError.Network("The session's project could not be determined")
            HeldLimit -> SendoraCloudAuthError.HeldGuestLimit("All held-guest slots are occupied")
        }
    }

    private enum class RotateOutcome { APPLIED, WITHHELD, DROPPED }

    private fun commit(tx: AuthTx.Install): CommitOutcome {
        val record = tx.record
        // 1. ProjectGuard — BEFORE any assignment (INV-15).
        when (verdictFor(record)) {
            ProjectVerdict.MISMATCH -> {
                val expected = machine.expectedProjectId!!
                val actual = actualProjectOf(record)
                if (tx.reason == InstallReason.HYDRATE) {
                    // → WITHHELD. NOTHING on disk: no write-forward, no schema bump,
                    // no `user_id` removal — rollback and re-init see identical bytes.
                    slot = AuthSlot.Withheld(record.refreshToken, record.accessToken, record.expiresAt,
                        WithheldInfo(expected, actual, record.user.id, record.user.isAnonymous))
                    cron.disarm()
                    onIdentityWithheld()
                    return CommitOutcome.Withheld
                }
                // A record minted by THIS process under THIS key: install nothing,
                // revoke what was minted, reject loudly (§8-Q14).
                background { client.post("/auth-service/token/revoke", mapOf("refreshToken" to record.refreshToken)) }
                return CommitOutcome.ProjectMismatch(expected, actual)
            }
            ProjectVerdict.UNKNOWN -> if (tx.reason == InstallReason.HYDRATE) {
                // Unreadable claim on a stored record: stay UNKNOWN, arm the gap-fill, write nothing.
                slot = AuthSlot.Limbo(record.refreshToken, record.accessToken, record.expiresAt, record.user)
                cron.arm { tickProactive() }
                return CommitOutcome.StayUnknown
            }
            ProjectVerdict.MATCH -> Unit
        }
        // 2. Identity CAS (INV-2): the session this result was derived from must still be current.
        if (tx.reason != InstallReason.HYDRATE && identityKey() != tx.expectIdentity) {
            background { client.post("/auth-service/token/revoke", mapOf("refreshToken" to record.refreshToken)) }
            return CommitOutcome.CasDropped
        }
        // 3. The previous slot: HOLD a guest (slot written FIRST), revoke a different identified account.
        val previous = (slot as? AuthSlot.Session)?.record
        var heldPrevious: HeldGuest? = null
        if (previous != null && previous.user.id != record.user.id) {
            if (previous.user.isAnonymous && tx.holdPreviousGuest) {
                val free = freeHeldIndex() ?: return CommitOutcome.HeldLimit
                heldPrevious = HeldGuest(
                    userId = previous.user.id, sid = previous.sid, refreshToken = previous.refreshToken,
                    tokenAtHold = previous.refreshToken, heldAt = nextHeldAt(), project = previous.projectClaim, autoRestore = true,
                )
                writeHeld(free, heldPrevious)
                heldReportPending = heldReportPending + previous.user.id
            } else if (!previous.user.isAnonymous && tx.revokePreviousIdentified) {
                val token = previous.refreshToken
                background { client.post("/auth-service/token/revoke", mapOf("refreshToken" to token)) }
            }
        }
        // 4. Dual-write the slot: the four frozen keys + `auth_session`, schema v2, drop the mint key.
        //    A hydrate writes ONLY to carry a legacy (4.25.0) record forward into
        //    `auth_session`; re-reading an `auth_session` the SDK wrote itself
        //    writes nothing (boot is a read).
        if (tx.reason != InstallReason.HYDRATE || tx.writeForward) writeSlot(record)
        if (tx.reason == InstallReason.MINT) storage.plainPut(AuthKeys.MINT_KEY, null)
        slot = AuthSlot.Session(record)
        // 5. Cron + parent hook.
        cron.arm { tickProactive() }
        onIdentityChange(record.user.id)
        // 6. Emission — confirmed transitions only (INV-7).
        heldPrevious?.let {
            emitAuthState(AuthStateChange.GuestHeld(it.userId, heldCount()))
            reportHeld(it)
        }
        when (val e = tx.emit) {
            Emit.None -> Unit
            is Emit.SignedIn -> emitAuthState(AuthStateChange.SignedIn(record.user, e.cause))
            is Emit.UserUpdated -> emitAuthState(AuthStateChange.UserUpdated(record.user, e.cause))
        }
        notifySettledIfNeeded()
        return CommitOutcome.Applied(heldPrevious != null)
    }

    private suspend fun commit(tx: AuthTx.Clear): Boolean {
        val s = slot
        val currentRefresh = when (s) {
            is AuthSlot.Session -> s.record.refreshToken
            is AuthSlot.Limbo -> s.refreshToken
            is AuthSlot.Withheld -> s.refreshToken
            AuthSlot.Empty -> return false
        }
        if (tx.expectRefresh != null && tx.expectRefresh != currentRefresh) return false
        clearSlotKeys()
        slot = AuthSlot.Empty
        heldReportPending = emptyList()
        cron.disarm()
        // Drop the clock-skew finding with everything else: a wipe is exactly when to inherit no beliefs.
        clockSkewConfirmed = false
        if (tx.stampHeldNoAutoRestore) {
            for (i in heldSlots.indices) {
                val g = heldSlots[i]?.parsed ?: continue
                if (g.autoRestore) writeHeld(i, g.copy(autoRestore = false))
            }
        }
        if (tx.effects.clearUserId || tx.effects.rotateDeviceId || tx.effects.clearQueue) onAnonymousWipe(tx.effects)
        emitAuthState(AuthStateChange.SignedOut(tx.reason, tx.endReason))
        tx.revokeToken?.let { token -> background { client.post("/auth-service/token/revoke", mapOf("refreshToken" to token)) } }
        notifySettledIfNeeded()
        return true
    }

    private fun commit(tx: AuthTx.UpdateUser): Boolean {
        val s = slot as? AuthSlot.Session ?: return false
        if (identityKey() != tx.expectIdentity) return false
        val record = s.record.copy(user = tx.user)
        writeSlot(record)
        slot = AuthSlot.Session(record)
        emitAuthState(AuthStateChange.UserUpdated(record.user, tx.cause))
        return true
    }

    private fun commit(tx: AuthTx.Rotate): RotateOutcome {
        when (val s = slot) {
            is AuthSlot.Session, is AuthSlot.Limbo -> {
                val currentRefresh = if (s is AuthSlot.Session) s.record.refreshToken else (s as AuthSlot.Limbo).refreshToken
                if (currentRefresh == tx.sent) return rotateCurrent(s, tx)
            }
            else -> Unit
        }
        // Routed by token: a held slot's refresh (restore / claim / discard presented it). CAS per slot.
        val i = heldSlots.indexOfFirst { it?.parsed?.refreshToken == tx.sent }
        if (i >= 0) {
            writeHeld(i, heldSlots[i]!!.parsed!!.copy(refreshToken = tx.refreshToken))
            return RotateOutcome.APPLIED
        }
        // Neither: a refresh that landed after signOut / replace — installing it
        // would resurrect a session the user left (P16). DROP.
        return RotateOutcome.DROPPED
    }

    private fun rotateCurrent(s: AuthSlot, tx: AuthTx.Rotate): RotateOutcome {
        val previousUser = (s as? AuthSlot.Session)?.record?.user ?: (s as? AuthSlot.Limbo)?.user
        val candidateUser = tx.user ?: previousUser
        val candidate = candidateUser?.let { AuthRecord(it, tx.accessToken, tx.refreshToken, tx.expiresAt) }
        val verdict = if (candidate != null) verdictFor(candidate) else projectVerdict(machine.expectedProjectId, tx.accessToken)
        when (verdict) {
            ProjectVerdict.MISMATCH -> {
                // Persist the rotation the server already performed (sent-token CAS)
                // and NOTHING else; uninstall the in-memory user; stop the cron.
                val expected = machine.expectedProjectId!!
                val actual = candidate?.let { actualProjectOf(it) }
                val userId = candidateUser?.id ?: decodeJwtPayload(tx.accessToken)?.optString("sub", "") ?: ""
                writeTokensOnly(tx.accessToken, tx.refreshToken, tx.expiresAt, candidateUser)
                slot = AuthSlot.Withheld(tx.refreshToken, tx.accessToken, tx.expiresAt,
                    WithheldInfo(expected, actual, userId, candidateUser?.isAnonymous ?: true))
                cron.disarm()
                onIdentityWithheld()
                emitAuthState(AuthStateChange.SessionWithheld(expected, actual, userId))
                notifySettledIfNeeded()
                return RotateOutcome.WITHHELD
            }
            ProjectVerdict.UNKNOWN -> {
                // The claim is unreadable on this token too: rotate, but do not
                // settle an UNKNOWN record — the next refresh re-judges it.
                if (s is AuthSlot.Session && candidate != null) {
                    writeSlot(candidate)
                    slot = AuthSlot.Session(candidate)
                } else {
                    writeTokensOnly(tx.accessToken, tx.refreshToken, tx.expiresAt, candidateUser)
                    slot = AuthSlot.Limbo(tx.refreshToken, tx.accessToken, tx.expiresAt, candidateUser)
                }
                return RotateOutcome.APPLIED
            }
            ProjectVerdict.MATCH -> {
                if (candidate == null) {
                    // UNKNOWN with no user in the response: rotate, stay UNKNOWN.
                    writeTokensOnly(tx.accessToken, tx.refreshToken, tx.expiresAt, null)
                    slot = AuthSlot.Limbo(tx.refreshToken, tx.accessToken, tx.expiresAt, null)
                    return RotateOutcome.APPLIED
                }
                writeSlot(candidate)
                slot = AuthSlot.Session(candidate)
                cron.arm { tickProactive() }
                if (previousUser == null) onIdentityChange(candidate.user.id)
                // A rotation is not a transition. Recovering an identity the SDK
                // had none of (the gap-fill from UNKNOWN) IS one and is reported as
                // the 4.12.0 `SignedIn` with no cause (parity: RN `recover`, 1.29.0);
                // a user object that CHANGED under the same session is `UserUpdated(REFRESH)`.
                if (previousUser == null) emitAuthState(AuthStateChange.SignedIn(candidate.user))
                else if (previousUser != candidate.user) emitAuthState(AuthStateChange.UserUpdated(candidate.user, AuthUserUpdatedCause.REFRESH))
                notifySettledIfNeeded()
                return RotateOutcome.APPLIED
            }
        }
    }

    private fun commit(tx: AuthTx.RotateHeld): Boolean {
        // CAS PER SLOT: re-read at write time; if the slot no longer holds `sent`, DROP.
        val g = heldSlots[tx.index]?.parsed ?: return false
        if (g.refreshToken != tx.sent) return false
        writeHeld(tx.index, g.copy(refreshToken = tx.newRefresh, project = if (tx.recordProject) tx.project else g.project))
        return true
    }

    private fun commit(tx: AuthTx.Release) {
        val g = heldSlots[tx.index] ?: return
        storage.securePut(AuthKeys.HELD_SLOT_KEYS[tx.index], null)
        heldSlots[tx.index] = null
        val userId = g.parsed?.userId ?: return
        heldReportPending = heldReportPending - userId
        if (!tx.silent) emitAuthState(AuthStateChange.GuestReleased(userId, tx.reason, tx.endReason))
    }

    private fun commit(tx: AuthTx.HeldReported) {
        if (tx.userId !in heldReportPending) return
        heldReportPending = heldReportPending - tx.userId
        (slot as? AuthSlot.Session)?.let { storage.securePut(AuthKeys.SESSION, AuthCodecs.sessionToJson(it.record, heldReportPending)) }
    }

    private fun commit(tx: AuthTx.MintKey) {
        storage.plainPut(AuthKeys.MINT_KEY, tx.key)
    }

    @Suppress("UNUSED_PARAMETER")
    private fun commit(tx: AuthTx.ClearStaleBlob) {
        storage.securePut(AuthKeys.USER, null)
        storage.securePut(AuthKeys.ACCESS, null)
        storage.securePutLong(AuthKeys.EXPIRES, 0L)
        storage.securePut(AuthKeys.SESSION, null)
    }

    @Suppress("UNUSED_PARAMETER")
    private fun commit(tx: AuthTx.DropLeftoverRecord) {
        storage.securePut(AuthKeys.SESSION, null)
    }

    // ── the writes themselves (called ONLY from the commit arms above) ────────

    /**
     * Dual-write: the four frozen keys (a downgrade reads a valid session) + `auth_session` + schema v2.
     * ⚠ ORDER IS LOAD-BEARING: the frozen keys FIRST, the record LAST — hydrate trusts a
     * record only when the frozen refresh key matches it, so a crash mid-write must never
     * leave a record whose frozen counterpart is missing.
     */
    private fun writeSlot(record: AuthRecord) {
        storage.securePut(AuthKeys.ACCESS, record.accessToken)
        storage.securePut(AuthKeys.REFRESH, record.refreshToken)
        storage.securePutLong(AuthKeys.EXPIRES, record.expiresAt)
        storage.securePut(AuthKeys.USER, AuthCodecs.userToJson(record.user).toString())
        storage.securePut(AuthKeys.SESSION, AuthCodecs.sessionToJson(record, heldReportPending))
        if (storage.plainGet(AuthKeys.SCHEMA_VERSION) != AuthKeys.SCHEMA_VERSION_V2) storage.plainPut(AuthKeys.SCHEMA_VERSION, AuthKeys.SCHEMA_VERSION_V2)
    }

    /** A server-performed rotation and nothing else (the withhold / unsettled paths): the token keys in both representations. */
    private fun writeTokensOnly(accessToken: String, refreshToken: String, expiresAt: Long, user: SendoraCloudAuthUser?) {
        storage.securePut(AuthKeys.ACCESS, accessToken)
        storage.securePut(AuthKeys.REFRESH, refreshToken)
        storage.securePutLong(AuthKeys.EXPIRES, expiresAt)
        if (storage.secureGet(AuthKeys.SESSION) != null && user != null) {
            storage.securePut(AuthKeys.SESSION, AuthCodecs.sessionToJson(AuthRecord(user, accessToken, refreshToken, expiresAt), heldReportPending))
        }
    }

    /** Exactly the slot's keys — never a held slot, never `user_id`, never the queue. */
    private fun clearSlotKeys() {
        storage.securePut(AuthKeys.ACCESS, null)
        storage.securePut(AuthKeys.REFRESH, null)
        storage.securePutLong(AuthKeys.EXPIRES, 0L)
        storage.securePut(AuthKeys.USER, null)
        storage.securePut(AuthKeys.SESSION, null)
    }

    private fun writeHeld(index: Int, guest: HeldGuest) {
        val json = guest.toJson()
        storage.securePut(AuthKeys.HELD_SLOT_KEYS[index], json)
        heldSlots[index] = HeldSlot(json, guest)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // END commit()
    // ═══════════════════════════════════════════════════════════════════════

    private companion object {
        const val HELD_CAPACITY = 5
        const val SWITCH_PAYLOAD_MAX_AGE_MS = 5L * 60_000L
        /** A [refreshAccessToken] `staleToken` that matches no real token: "do not serve the cache". */
        const val STALE_NONE = "\u0000stale"
    }
}

/**
 * Result of [SendoraCloudAuth.unlink].
 *
 * `removed` can exceed 1: an account may hold more than one row for a provider
 * (distinct provider user ids across projects), and unlinking takes all of them.
 */
data class UnlinkResult(
    val provider: String,
    val removed: Int,
    val remaining: Int,
)

/**
 * The production [RefreshCron]: a 60 s coroutine tick plus one tick on app
 * foreground (`ProcessLifecycleOwner.ON_START`, reflection-loaded so the SDK
 * does not hard-require androidx.lifecycle). Armed and disarmed only by the
 * auth commit funnel.
 */
internal class CoroutineRefreshCron(private val scope: CoroutineScope) : RefreshCron {
    private var job: Job? = null
    private var lifecycleObserver: Any? = null

    override val isArmed: Boolean get() = job?.isActive == true

    override fun arm(tick: suspend () -> Unit) {
        if (isArmed) return
        job = scope.launch {
            while (isActive) {
                runCatching { tick() }
                delay(60_000L)
            }
        }
        registerLifecycleObserver(tick)
    }

    override fun disarm() {
        job?.cancel()
        job = null
        unregisterLifecycleObserver()
    }

    private fun registerLifecycleObserver(tick: suspend () -> Unit) {
        try {
            val ownerClass = Class.forName("androidx.lifecycle.ProcessLifecycleOwner")
            val owner = ownerClass.getMethod("get").invoke(null)
            val lifecycle = owner.javaClass.getMethod("getLifecycle").invoke(owner)
            val observerClass = Class.forName("androidx.lifecycle.DefaultLifecycleObserver")
            val handler = java.lang.reflect.Proxy.newProxyInstance(
                observerClass.classLoader,
                arrayOf(observerClass),
            ) { _, method, _ ->
                if (method.name == "onStart") {
                    scope.launch { runCatching { tick() } }
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

// MARK: access-token expiry

/**
 * True when the token's OWN `exp` claim is still in the future by the device
 * clock — or when the token carries no readable `exp` at all.
 *
 * ⚠ Unreadable → `true` is deliberate, and it is what makes this safe to layer
 * UNDER the tracked-deadline check rather than in place of it. An opaque or
 * non-JWT access token keeps exactly the behaviour it had before this guard
 * existed; the pair can only ever refresh earlier, never later.
 *
 * ⚠ Never derive the tracked deadline FROM `exp`. The two guards fail in
 * opposite directions and that is the point — `now + expiresIn` is
 * skew-INVARIANT (a permanently wrong clock cancels on both sides) and blind to
 * a clock that MOVES, while `exp` is written in the server's frame and survives
 * a clock step but is wrong by the full offset on a permanently wrong clock.
 */
internal fun accessTokenExpIsFuture(token: String, nowMs: Long): Boolean {
    val exp = decodeJwtExp(token) ?: return true
    return nowMs < exp * 1000.0
}

/**
 * Read `exp` out of a JWT payload. The signature is never verified
 * client-side — the server is the only authority on validity; this is a
 * freshness hint, not an authorization decision.
 */
internal fun decodeJwtExp(token: String): Double? = try {
    val json = decodeJwtPayload(token)
    if (json != null && json.has("exp")) {
        val exp = json.getDouble("exp")
        if (exp.isFinite()) exp else null
    } else {
        null
    }
} catch (_: Exception) {
    null
}
