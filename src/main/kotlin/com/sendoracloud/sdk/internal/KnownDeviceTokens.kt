package com.sendoracloud.sdk.internal

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Locale

/**
 * 4.28.0 — the codec behind [AuthKeys.KNOWN_DEVICE_TOKENS]. Pure (no storage,
 * no clock of its own) so the JVM suite pins the bound and the ordering.
 *
 * The map is keyed by SHA-256 of the normalised email, never the address
 * itself: the value is a lockout exemption, and the device has no need to
 * keep a list of every email typed into it.
 */
internal object KnownDeviceTokens {
    /** At most this many accounts are remembered; the oldest falls off. */
    const val MAX_ENTRIES = 20

    /** The backend accepts a `knownDeviceToken` of up to 2048 chars on `/login`. */
    const val MAX_TOKEN_LENGTH = 2048

    /** The backend's normalisation: trimmed, lower-cased (ROOT locale — a Turkish-locale device must agree). */
    fun normaliseEmail(email: String): String = email.trim().lowercase(Locale.ROOT)

    fun keyFor(email: String): String =
        MessageDigest.getInstance("SHA-256").digest(normaliseEmail(email).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    data class Entry(val key: String, val token: String, val at: Long)

    fun decode(raw: String?): List<Entry> {
        if (raw.isNullOrEmpty()) return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { i ->
                val o = array.optJSONObject(i) ?: return@mapNotNull null
                val k = o.optString("k").takeIf { it.isNotEmpty() } ?: return@mapNotNull null
                val t = o.optString("t").takeIf { isUsable(it) } ?: return@mapNotNull null
                Entry(k, t, o.optLong("at", 0L))
            }
        }.getOrDefault(emptyList())
    }

    fun encode(entries: List<Entry>): String {
        val array = JSONArray()
        entries.forEach { e -> array.put(JSONObject().put("k", e.key).put("t", e.token).put("at", e.at)) }
        return array.toString()
    }

    fun isUsable(token: String?): Boolean = !token.isNullOrEmpty() && token.length <= MAX_TOKEN_LENGTH

    fun lookup(entries: List<Entry>, email: String): String? {
        val key = keyFor(email)
        return entries.firstOrNull { it.key == key }?.token
    }

    /** The map without [email]'s entry (deleteAccount). */
    fun remove(entries: List<Entry>, email: String): List<Entry> {
        val key = keyFor(email)
        return entries.filter { it.key != key }
    }

    /** The map after remembering [token] for [email]: that account moves to the front, at most [MAX_ENTRIES] kept. */
    fun put(entries: List<Entry>, email: String, token: String, now: Long): List<Entry> {
        val key = keyFor(email)
        return (listOf(Entry(key, token, now)) + entries.filter { it.key != key }).take(MAX_ENTRIES)
    }
}
