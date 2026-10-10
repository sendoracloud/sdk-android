package com.sendoracloud.sdk

/**
 * ADR-033 wave 1 (4.26.0) — the public types of the auth state machine, in
 * LOCKSTEP with the RN reference (`packages/shared/src/auth-machine/types.ts`):
 * same verbs, same result shapes (sealed classes with resolver METHODS where
 * RN has closures), same wire names, same error codes.
 *
 * ⚠ NORMATIVE — `when` over [AuthStatus], [AuthSignedInCause],
 * [GuestReleasedReason] or [AuthStateChange] MUST carry an `else` branch (the
 * Swift `@unknown default` rule). `WITHHELD` is free NOW because the type is
 * new; any LATER value lands in a MAJOR for this SDK, because an exhaustive
 * `when` expression written today would stop compiling.
 */

/**
 * The five client states (ADR-033 §3.2). `UNKNOWN` ≠ `SIGNED_OUT` and
 * `WITHHELD` ≠ `SIGNED_OUT`: `currentUser` is `null` in all three, so
 * [SendoraCloudAuth.status] is the ONLY way to tell them apart.
 *
 *  - [UNKNOWN]     not hydrated, or a refresh token is on disk but the user is
 *                  not readable (or its project claim is). The single gap-fill
 *                  refresh settles it. A mint here is QUEUED, never executed.
 *  - [SIGNED_OUT]  no refresh token. The ONLY state in which a mint executes.
 *  - [ANONYMOUS]   refresh token + `user.isAnonymous == true`.
 *  - [IDENTIFIED]  refresh token + `user.isAnonymous == false`.
 *  - [WITHHELD]    a stored session refused because its JWT `project` claim
 *                  disagrees with `SendoraCloudConfig.expectedProjectId`
 *                  (opt-in). Nothing on disk was touched; exits are
 *                  [SendoraCloudAuth.discardWithheld] or the matching key.
 */
enum class AuthStatus(val wire: String) {
    UNKNOWN("unknown"),
    SIGNED_OUT("signed_out"),
    ANONYMOUS("anonymous"),
    IDENTIFIED("identified"),
    WITHHELD("withheld"),
}

/**
 * Why a [AuthStateChange.SignedIn] fired. [RESTORE] ⇒ re-register push (a held
 * guest's push tokens were erased if it had been deleted elsewhere); [LINK] =
 * the legacy same-`sub` promotion the legacy-signature methods (`signUp`,
 * `loginSocial(link = true)`, `signInWithPlayGames(link = true)`) keep emitting
 * for compatibility (ADR-033 §8-Q18). `null` on a pre-4.26.0 style emission
 * (the replay on subscribe).
 */
enum class AuthSignedInCause(val wire: String) {
    MINT("mint"),
    SIGN_IN("sign_in"),
    RESTORE("restore"),
    LINK("link"),
}

/** What changed the user object WITHOUT changing the `sub` ([AuthStateChange.UserUpdated]). */
enum class AuthUserUpdatedCause(val wire: String) {
    LINK("link"),
    UNLINK("unlink"),
    EMAIL_VERIFIED("email_verified"),
    REFRESH("refresh"),
    MERGE("merge"),
}

/**
 * Every exit from a held slot names one ([AuthStateChange.GuestReleased]).
 * ⚠ [DEAD] = "the server said unavailable when the held token was presented"
 * (`endReason` ∈ deleted|revoked|expired). It is NOT an erasure signal and it
 * conflates deleted-elsewhere, merged-elsewhere and expired: a UI must say
 * "unavailable", never "progress lost".
 */
enum class GuestReleasedReason(val wire: String) {
    CLAIMED("claimed"),
    RESTORED("restored"),
    DISCARDED("discarded"),
    DEAD("dead"),
    RESET("reset"),
}

/**
 * One held guest as [SendoraCloudAuth.heldGuests] reports it — the slot MINUS
 * its tokens (never exposed). `heldAt` is ms since epoch; the list is ordered
 * newest first. `autoRestore == false` ⇔ the guest was held when the
 * then-current account was deleted: only an explicit
 * [SendoraCloudAuth.restoreHeldGuest] revives it. `project` is the JWT claim
 * recorded at hold, `null` when unreadable. Best-effort: nothing refreshes a
 * held token in the background, so a listed guest may already be gone
 * server-side until its token is presented.
 */
data class HeldGuestSummary(
    val userId: String,
    val heldAt: Long,
    val autoRestore: Boolean,
    val project: String?,
)

/**
 * What [SendoraCloudAuth.withheld] returns while `status() == WITHHELD`. Never
 * exposes tokens. `userId` is there so a `sub`-keyed backend can record
 * oldSub → newSub BEFORE calling [SendoraCloudAuth.discardWithheld].
 */
data class WithheldInfo(
    val expectedProjectId: String,
    val actualProjectId: String?,
    val userId: String,
    val isAnonymous: Boolean,
) {
    val reason: String get() = "project_mismatch"
}

/**
 * What a SWITCH replaced ([SignInResult.Done.previous]). `held == true` ⇔ the
 * previous session was a guest and is now in a held slot. `isAnonymous ==
 * false` ⇒ an identified → identified switch: the app must skip any merge and
 * reset local save state.
 */
data class PreviousSession(
    val userId: String,
    val isAnonymous: Boolean,
    val held: Boolean,
)

/**
 * The typed input of [SendoraCloudAuth.link] / [SendoraCloudAuth.signInWith]
 * — one closed set instead of nine method signatures. Each member carries
 * exactly the wire fields of its sign-in / link schema MINUS the guest hint
 * (`prevAnonRefreshToken`, `linkAnonymous`, `onCredentialInUse`): a 4.26.0
 * sign-in body never carries a guest credential (INV-3), so there is no field
 * to put it in. Game Center is iOS-only and is not modelled here.
 */
sealed class Credential {
    data class Password(val email: String, val password: String) : Credential()

    /**
     * An IdP credential. `provider` ∈ google | github | apple | microsoft |
     * linkedin | facebook | twitter | discord; pass `code` (+ `redirectUri`) OR
     * `idToken`.
     */
    data class Social(
        val provider: String,
        val code: String? = null,
        val idToken: String? = null,
        val redirectUri: String? = null,
        val codeVerifier: String? = null,
        val appleFirstName: String? = null,
        val appleLastName: String? = null,
    ) : Credential()

    /**
     * Google Play Games. `serverAuthCode` is single-use and opaque, so a stale
     * refusal cannot be re-verified from it alone; supply `playerId`
     * (`PlayGames.getPlayersClient(activity).currentPlayer.playerId`) so a
     * re-fetched credential can be compared to the one the player confirmed
     * ([LinkResult.CredentialInUse.switchAccount], INV-14).
     */
    data class PlayGames(val serverAuthCode: String, val playerId: String? = null) : Credential()

    data class MagicLink(val token: String) : Credential()

    data class EmailOtp(val email: String, val code: String) : Credential()

    /** The WebAuthn assertion as produced by the platform authenticator; forwarded to `passkeys/authenticate/finish`. */
    data class Passkey(val assertion: Map<String, Any?>) : Credential()

    data class Mfa(val challengeToken: String, val code: String) : Credential()
}

/** The result of [SendoraCloudAuth.signInWith] / [LinkResult.CredentialInUse.switchAccount]. */
sealed class SignInResult {
    /**
     * `previous` is what the switch replaced (`null` from `SIGNED_OUT`);
     * `reactivated` surfaces a cancelled pending self-service deletion.
     */
    data class Done(
        val user: SendoraCloudAuthUser,
        val previous: PreviousSession?,
        val reactivated: Boolean,
    ) : SignInResult()

    /**
     * The account has MFA enabled. [verify] completes the challenge; the MFA
     * context lives in this result, never in a nullable field cleared by hand,
     * and abandoning it leaves the current session exactly as it was.
     */
    class MfaRequired internal constructor(
        val challengeToken: String,
        private val verifier: suspend (String) -> Result<SignInResult>,
    ) : SignInResult() {
        suspend fun verify(code: String): Result<SignInResult> = verifier(code)
    }
}

/** `identity` = the provider identity is owned by another account; `email` = its verified email is. */
enum class LinkCollision(val wire: String) {
    IDENTITY("identity"),
    EMAIL("email");

    companion object {
        fun fromWire(raw: String?): LinkCollision? = entries.firstOrNull { it.wire == raw }
    }
}

/**
 * The result of [SendoraCloudAuth.link] — the ONLY upgrade verb (INV-4).
 * Nothing is mutated on the two refusals.
 *
 *  - [Done] with `alreadyLinked == true` — the same identity is already on this
 *    account: a quiet 200, NO event, NO revoke of other sessions, NO step-up.
 *    This is the launch-time call of a returning identified player.
 *  - [Done] with `upgraded == true` — the caller was a guest and was promoted in
 *    place (same `sub`, rotated tokens installed); `false` on an identified
 *    attach (no rotation).
 *  - [CredentialInUse] — owned by another account (409). [CredentialInUse.switchAccount]
 *    is the ONLY path from a refused link to a sign-in and is BOUND to the
 *    refused credential (INV-14).
 *  - [RecentAuthRequired] — the credential is fine, the session is too old to
 *    attach a NEW credential (403). State unchanged. There is deliberately NO
 *    `reauthenticate(credential)` here: re-auth must use a credential already
 *    on the current account.
 */
sealed class LinkResult {
    data class Done(
        val user: SendoraCloudAuthUser,
        val upgraded: Boolean,
        val alreadyLinked: Boolean,
    ) : LinkResult()

    class CredentialInUse internal constructor(
        val provider: String,
        val collision: LinkCollision?,
        private val switcher: suspend ((suspend () -> Credential)?) -> Result<SignInResult>,
    ) : LinkResult() {
        /**
         * Sign in to the account that owns the refused credential — a plain
         * SWITCH: from a guest the guest is HELD on this device; from an
         * identified account nothing is held (`previous.isAnonymous == false`).
         *
         * Bound to the refused credential: the same payload is re-presented when
         * it is under 5 minutes old; after that the SDK will not sign the player
         * into whatever the device now says — pass [refetch] to obtain the
         * credential again natively, and the SDK compares it to the refused one
         * (Play Games `playerId`, email, OIDC `sub`) and aborts with
         * `credential_changed` on a mismatch. A stale refusal with no
         * [refetch] aborts the same way.
         */
        suspend fun switchAccount(refetch: (suspend () -> Credential)? = null): Result<SignInResult> = switcher(refetch)

        /** Drop the context; the current session is untouched (it already was). */
        fun keepCurrent() = Unit
    }

    object RecentAuthRequired : LinkResult()
}

/** Server-side merge counters ([ClaimResult.stats]); a non-zero `profilesDropped` is the ordinary collision case. */
data class MergeStats(
    val mergedUserId: String,
    val deletedAnonymousId: String,
    val eventsReassigned: Int,
    val profilesReassigned: Int,
    val profilesDropped: Int,
    val entitiesReassigned: Int,
    val entitiesDropped: Int,
    val pushTokensReassigned: Int,
)

/** The result of [SendoraCloudAuth.claimHeldGuest]. */
data class ClaimResult(val user: SendoraCloudAuthUser, val stats: MergeStats)
