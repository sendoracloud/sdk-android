package com.sendoracloud.sdk.internal

/**
 * ADR-033 INV-1 / INV-10 — the ONE module that names the on-device auth keys.
 *
 * Every key the auth machine writes is a literal here and nowhere else, so
 * "the storage key names appear in exactly one module per SDK" (INV-1's
 * source guard) is a property of the file layout, not a convention. The
 * conformance suite asserts that the secure key set below is EXACTLY the four
 * frozen keys + `auth_session` + the K fixture slot names, and that every key
 * the machine writes during a replay is a member of it — a held-slot name
 * built dynamically (`"held_" + userId`) is not in the set and turns the suite
 * red (§5 wave 1 "build a held key name dynamically → red").
 *
 * ⚠ ADR-023 FROZEN. The four `auth_*` keys and `schema_version` are read by
 * every installed app; never rename or remove one. `auth_session` and
 * `auth_held_0..4` are ADDITIVE (4.26.0) — a 4.25.0 simply does not read them.
 */
internal object AuthKeys {
    // ── the four frozen keys (ADR-023 §3.4) — format unchanged ──────────────
    const val ACCESS = "auth_access_token"
    const val REFRESH = "auth_refresh_token"
    /** Unix-millis `Long` (EncryptedSharedPreferences `putLong`). 0 = unknown. */
    const val EXPIRES = "auth_access_expires"
    /** JSON-encoded user record (legacy shape + an OPTIONAL `project` key since 4.26.0). */
    const val USER = "auth_user"

    /**
     * ADR-033 wave 1 — the single session record, written beside the four
     * frozen keys on every install (dual-write), read FIRST on hydrate, written
     * forward from the legacy keys when absent. Carries the user, the token
     * trio, the deadline and the non-secret `heldReportPending` list. NEVER
     * carries held-guest material (§3.2: held slots are their own keys).
     */
    const val SESSION = "auth_session"

    /** K = 5 FIXED held-guest slots (`auth_held_0` … `auth_held_4`). */
    val HELD_SLOT_KEYS: List<String> = List(5) { "auth_held_$it" }

    /** The five keys that make up the current-session slot; a ClearTx removes exactly these. */
    val SLOT_KEYS: List<String> = listOf(ACCESS, REFRESH, EXPIRES, USER, SESSION)

    /** Everything routed to EncryptedSharedPreferences — the INV-10 `SECURE_KEYS` list. */
    val SECURE_KEYS: List<String> = SLOT_KEYS + HELD_SLOT_KEYS

    /** The hydrate read list (`AUTH_HYDRATE_KEYS`): the slot + every held slot. */
    val HYDRATE_KEYS: List<String> = SLOT_KEYS + HELD_SLOT_KEYS

    // ── plain (non-secret) tier ─────────────────────────────────────────────
    /** ADR-023 §5 marker in the plain `sendora_sdk` prefs. "1" until wave 1; "2" once `auth_session` exists. */
    const val SCHEMA_VERSION = "schema_version"
    const val SCHEMA_VERSION_V1 = "1"
    const val SCHEMA_VERSION_V2 = "2"
    /**
     * ADR-033 B10 — the per-ATTEMPT mint key, persisted in the non-secret tier
     * until MINT_OK so a retry after a process death re-presents the same key
     * and gets the same guest back. Not a credential (the server stores a hash
     * with a 24 h expiry); cleared by the mint's install commit.
     */
    const val MINT_KEY = "auth_mint_key"

    // ── device-scoped secrets (4.28.0) — encrypted, OUTSIDE the slot ────────
    /**
     * F23 / F67 — the server's `knownDeviceToken`s, one per account this
     * device signed into with a password: a JSON array of
     * `{k: sha256(normalised email), t: token, at: unix ms}`, newest first,
     * at most 20. The token authenticates NOTHING; it only exempts this device
     * from the account-wide login lockouts (`login-admission.ts`).
     *
     * ⚠ Deliberately NOT in [SECURE_KEYS] / [SLOT_KEYS]: those are the
     * session's keys, and a sign-out clears exactly the slot — this map must
     * survive a sign-out AND `SendoraCloud.reset()` (the next sign-in on this
     * device is the one it is for). Only `deleteAccount()` removes an entry —
     * the deleted account's. Encrypted all the same
     * ([DEVICE_SECRET_KEYS] routes it to the secure tier); never logged.
     */
    const val KNOWN_DEVICE_TOKENS = "auth_known_devices"

    /** Secure-tier keys that are NOT session state (survive sign-out and reset; deleteAccount prunes its own entry). */
    val DEVICE_SECRET_KEYS: List<String> = listOf(KNOWN_DEVICE_TOKENS)
}

/**
 * The two closed sets the refresh verdicts are classified by — the Kotlin
 * copies of `DEAD_CODES` / `RELEASE_HELD_ON_END_REASONS` in
 * `packages/shared/src/auth-machine/states.ts`. The conformance suite asserts
 * they EQUAL the fixture's (`deadCodes`, `releaseHeldOnEndReasons`), and the
 * machine reads them from here, so a widened set is both a fixture diff and a
 * behavioural red.
 */
internal object AuthMachineSets {
    /** ONLY the per-user verdict ends a session (INV-6) — never a generic 401 / 429 / 5xx. */
    val DEAD_CODES: Set<String> = setOf("INVALID_REFRESH_TOKEN")
    /** A held slot is released ONLY on these `endReason`s — never `reuse`, never absent. */
    val RELEASE_HELD_ON_END_REASONS: Set<String> = setOf("deleted", "revoked", "expired")
}
