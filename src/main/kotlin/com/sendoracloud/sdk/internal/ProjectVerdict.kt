package com.sendoracloud.sdk.internal

import org.json.JSONObject
import org.json.JSONTokener

/**
 * ADR-033 INV-15 — `projectVerdict()`, the ProjectGuard every InstallTx is
 * judged by BEFORE any assignment. A VERBATIM port of
 * `packages/shared/src/auth-machine/project-verdict.ts`; the shared fixture
 * (`auth-transitions.conformance.json` → `projectVerdictCases`) carries
 * LITERAL JWTs so this port is replayed by `AuthMachineConformanceTest` with
 * nothing but a decoder.
 *
 * WHY A PURE FUNCTION. `withheld` is "a pure function of (disk record, config),
 * recomputed every hydrate, never persisted" — so a re-init with the right key
 * or a rollback needs no migration. That holds only if the verdict reads
 * nothing but its two arguments: no clock (expiry is irrelevant — a stale token
 * still names its project truthfully), no network, no storage, and no platform
 * base64 (`android.util.Base64` is a stub on the JVM; `java.util.Base64`'s URL
 * decoder refuses the standard alphabet and tolerates padding differently per
 * JDK). The decoders below are the shared ones, byte for byte.
 *
 * The three answers, and why absent ≠ match (§3.3, §8-Q13):
 *
 *   expected unset                                   → MATCH    (guard off)
 *   token missing / undecodable / claim KEY absent   → UNKNOWN  (NOT match: a
 *       pre-s58.276 token says nothing about its project; the SDK stays
 *       `unknown` and lets the refresh answer)
 *   claim === null                                   → MISMATCH (the server
 *       emits an EXPLICIT null for the org-wide pool; under a project-bound
 *       expectedProjectId an org-wide session is the wrong tenant)
 *   claim is a string                                → equal ? MATCH : MISMATCH
 *
 * ⚠ ADVISORY (a client consistency check against a wrong-key build), not an
 * authorization boundary, and it never produces a dead-token verdict
 * (INV-6/INV-15).
 */
internal enum class ProjectVerdict(val wire: String) {
    MATCH("match"),
    MISMATCH("mismatch"),
    UNKNOWN("unknown"),
}

/** The JWT claim this guard reads. Emitted ALWAYS by the backend since s58.276. */
internal const val PROJECT_CLAIM = "project"

internal fun projectVerdict(expectedProjectId: String?, accessJwt: String?): ProjectVerdict {
    // Guard off. Checked FIRST so an SDK without the opt-in never pays for a
    // decode and never reports UNKNOWN on a legacy token.
    if (expectedProjectId == null) return ProjectVerdict.MATCH

    val payload = decodeJwtPayload(accessJwt) ?: return ProjectVerdict.UNKNOWN

    // Key presence, not truthiness: `{ project: null }` is PRESENT and means
    // "org-wide pool"; `{}` is ABSENT and means "minted before the claim
    // existed". Collapsing those two is the exact mistake the fixture
    // `claim_absent` exists to catch (§5 wave 1 "treat an absent claim as match → red").
    if (!payload.has(PROJECT_CLAIM)) return ProjectVerdict.UNKNOWN

    if (payload.isNull(PROJECT_CLAIM)) return ProjectVerdict.MISMATCH
    val claim = payload.opt(PROJECT_CLAIM)
    if (claim is String) return if (claim == expectedProjectId) ProjectVerdict.MATCH else ProjectVerdict.MISMATCH

    // Present, decodable, and not a string — the server never emits this shape.
    // It is a value that disagrees with the expected string, so it is a
    // mismatch, not an unknown: UNKNOWN would park the SDK waiting for a
    // refresh to "settle" a claim that is already settled and wrong.
    return ProjectVerdict.MISMATCH
}

/**
 * Decode a compact JWS payload (`header.payload.signature`) WITHOUT verifying
 * the signature. The verdict only needs to READ a claim from a token the SDK
 * already holds (the server verifies on every request); verification here
 * would need the JWKS, i.e. the network, which the verdict must not touch.
 *
 * Returns `null` for anything that is not a three-segment token whose second
 * segment base64url-decodes to a UTF-8 JSON OBJECT. Arrays, scalars and
 * malformed input are all "undecodable".
 */
internal fun decodeJwtPayload(token: String?): JSONObject? {
    if (token.isNullOrEmpty()) return null
    val parts = token.split(".")
    if (parts.size != 3) return null
    val bytes = decodeBase64Url(parts[1]) ?: return null
    val json = decodeUtf8(bytes) ?: return null
    val parsed = try {
        JSONTokener(json).nextValue()
    } catch (_: Exception) {
        return null
    }
    return parsed as? JSONObject
}

// ─── base64url (RFC 4648 §5) → bytes, no platform decoder ───────────────────
//
// Accepts the url-safe alphabet (`-` `_`) AND the standard one (`+` `/`) so a
// token that was re-encoded by a careless proxy still decodes; tolerates the
// optional `=` padding JWS omits. Any other character, or a length ≡ 1 (mod 4)
// after padding removal (impossible for real base64), is "undecodable".

private val B64_LOOKUP: IntArray = IntArray(128) { -1 }.also { table ->
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for (i in alphabet.indices) table[alphabet[i].code] = i
    table['-'.code] = 62
    table['_'.code] = 63
    table['+'.code] = 62
    table['/'.code] = 63
}

internal fun decodeBase64Url(input: String): ByteArray? {
    var end = input.length
    while (end > 0 && input[end - 1] == '=') end--
    if (end % 4 == 1) return null
    val out = ByteArray((end * 3) / 4)
    var buffer = 0
    var bits = 0
    var o = 0
    for (i in 0 until end) {
        val code = input[i].code
        val v = if (code < 128) B64_LOOKUP[code] else -1
        if (v < 0) return null
        buffer = (buffer shl 6) or v
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out[o++] = ((buffer shr bits) and 0xff).toByte()
        }
    }
    return if (o == out.size) out else out.copyOf(o)
}

// ─── UTF-8 → string, strict ─────────────────────────────────────────────────
//
// A JWT payload is JSON and JSON is UTF-8; the `name` claim can carry any
// script. A decoder that only handled ASCII would report a perfectly good token
// as "undecodable" for a player whose display name is in Devanagari — and
// `unknown` on every hydrate is a session that never settles. Strict: overlong
// forms, lone surrogates and truncated sequences return `null` (the JDK's
// `String(bytes, UTF_8)` silently substitutes U+FFFD instead, which would make
// this port disagree with the shared one on malformed input).

internal fun decodeUtf8(bytes: ByteArray): String? {
    val out = StringBuilder()
    var i = 0
    val n = bytes.size
    while (i < n) {
        val b0 = bytes[i].toInt() and 0xff
        var cp: Int
        val need: Int
        when {
            b0 < 0x80 -> { cp = b0; need = 0 }
            b0 in 0xc2..0xdf -> { cp = b0 and 0x1f; need = 1 }
            b0 in 0xe0..0xef -> { cp = b0 and 0x0f; need = 2 }
            b0 in 0xf0..0xf4 -> { cp = b0 and 0x07; need = 3 }
            else -> return null // 0x80–0xC1 continuation/overlong lead, 0xF5+ out of range
        }
        if (i + need >= n) return null // truncated multi-byte sequence
        for (k in 1..need) {
            val b = bytes[i + k].toInt() and 0xff
            if ((b and 0xc0) != 0x80) return null // not a continuation byte
            cp = (cp shl 6) or (b and 0x3f)
        }
        // Reject overlong encodings and the surrogate range / out-of-range code points.
        if ((need == 2 && cp < 0x800) ||
            (need == 3 && (cp < 0x10000 || cp > 0x10ffff)) ||
            (cp in 0xd800..0xdfff)
        ) {
            return null
        }
        if (cp > 0xffff) {
            val v = cp - 0x10000
            out.append((0xd800 + (v shr 10)).toChar())
            out.append((0xdc00 + (v and 0x3ff)).toChar())
        } else {
            out.append(cp.toChar())
        }
        i += need + 1
    }
    return out.toString()
}
