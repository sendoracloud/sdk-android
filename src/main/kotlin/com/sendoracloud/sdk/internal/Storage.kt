package com.sendoracloud.sdk.internal

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Persistent storage.
 *  - Non-sensitive (`isFirstLaunch`, `sessionId`) lives in plain SharedPreferences.
 *  - `cachedUserId` + `deviceId` + auth tokens live in EncryptedSharedPreferences
 *    (AES256-GCM, key stored in AndroidKeyStore).
 *  - Event queue persisted with `userId` + `traits` stripped — they'll be
 *    re-injected from `currentUserId` at send time.
 *
 * **Critical:** if EncryptedSharedPreferences cannot be initialised (corrupt
 * Keystore, missing AndroidX dep), token writes are REFUSED rather than
 * silently downgraded to plaintext SharedPreferences. The previous fallback
 * exposed access + refresh tokens in cleartext on disk — full account
 * takeover on rooted devices or via post-uninstall data extraction.
 */
internal class Storage(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("sendora_sdk", Context.MODE_PRIVATE)

    /**
     * Null when secure storage is unavailable. Every secure getter/setter
     * checks this and refuses the operation if null — token persistence
     * fails closed instead of degrading to plaintext.
     */
    private val securePrefs: SharedPreferences? = runCatching {
        val master = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "sendora_sdk_secure",
            master,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }.getOrElse { err ->
        SendoraCloudLogger.error(
            "EncryptedSharedPreferences init failed — auth tokens will not persist. Refusing plaintext fallback.",
            err,
        )
        null
    }

    /** True when secure storage is available. Auth.signIn etc. should
     *  surface a configuration error to the consumer if false. */
    val isSecureAvailable: Boolean get() = securePrefs != null

    /**
     * On-device schema/format-version marker (ADR-023 §5). Non-sensitive →
     * plain SharedPreferences (NOT EncryptedSharedPreferences). Written once
     * at init while the format is still v1, so a future SDK can branch a
     * read-old→write-new migration on it (`if (stored < N) migrate()`)
     * instead of guessing. New key — read nowhere yet; never rename existing
     * keys (frozen per ADR-023 §3.4).
     */
    fun ensureSchemaVersion() {
        if (!prefs.contains("schema_version")) {
            prefs.edit().putString("schema_version", "1").apply()
        }
    }

    var isFirstLaunch: Boolean
        get() = !prefs.getBoolean("launched", false)
        set(value) { prefs.edit().putBoolean("launched", !value).apply() }

    private val _sessionLock = Any()

    var sessionId: String
        get() = synchronized(_sessionLock) {
            prefs.getString("session_id", null) ?: run {
                val new = UUID.randomUUID().toString()
                prefs.edit().putString("session_id", new).apply()
                new
            }
        }
        set(value) = synchronized(_sessionLock) {
            prefs.edit().putString("session_id", value).apply()
        }

    var cachedUserId: String?
        get() = securePrefs?.getString("user_id", null)
        set(value) {
            val sp = securePrefs ?: return
            val e = sp.edit()
            if (value != null) e.putString("user_id", value) else e.remove("user_id")
            e.apply()
        }

    /**
     * Process-lifetime fallback id, minted at most once when secure storage
     * is unavailable. Cached so every caller in the same process sees ONE id
     * (otherwise each getter returned a fresh UUID, fanning a single install
     * out to multiple device ids across attribution/deferred reports and
     * breaking backend dedup). Guarded by `_sessionLock`.
     */
    private var ephemeralDeviceId: String? = null

    val deviceId: String
        get() = synchronized(_sessionLock) {
            val sp = securePrefs
            if (sp == null) {
                // Cannot persist — return a per-process random id so events
                // still have a STABLE id within the process. Cache it so all
                // callers agree; log loudly the first time so the developer
                // notices.
                ephemeralDeviceId?.let { return it }
                SendoraCloudLogger.error("deviceId requested but secure storage unavailable; returning ephemeral id")
                val ephemeral = UUID.randomUUID().toString()
                ephemeralDeviceId = ephemeral
                return ephemeral
            }
            val existing = sp.getString("device_id", null)
            if (existing != null) return existing
            val newId = UUID.randomUUID().toString()
            sp.edit().putString("device_id", newId).apply()
            newId
        }

    fun regenerateDeviceId() {
        synchronized(_sessionLock) {
            ephemeralDeviceId = null
            securePrefs?.edit()?.remove("device_id")?.apply()
        }
    }

    // --- Auth Service tokens (EncryptedSharedPreferences ONLY) ---

    var authAccessToken: String?
        get() = securePrefs?.getString("auth_access_token", null)
        set(value) {
            val sp = securePrefs
            if (sp == null) {
                SendoraCloudLogger.error("Refusing to persist auth token — secure storage unavailable")
                return
            }
            val e = sp.edit()
            if (value != null) e.putString("auth_access_token", value) else e.remove("auth_access_token")
            e.apply()
        }

    var authRefreshToken: String?
        get() = securePrefs?.getString("auth_refresh_token", null)
        set(value) {
            val sp = securePrefs
            if (sp == null) {
                SendoraCloudLogger.error("Refusing to persist refresh token — secure storage unavailable")
                return
            }
            val e = sp.edit()
            if (value != null) e.putString("auth_refresh_token", value) else e.remove("auth_refresh_token")
            e.apply()
        }

    /** Unix-millis when the cached access token expires. 0 = unknown. */
    var authAccessExpiresAt: Long
        get() = securePrefs?.getLong("auth_access_expires", 0L) ?: 0L
        set(value) {
            val sp = securePrefs ?: return
            val e = sp.edit()
            if (value > 0) e.putLong("auth_access_expires", value) else e.remove("auth_access_expires")
            e.apply()
        }

    /** JSON-encoded `AuthUser`. Decoded by SendoraCloudAuth. */
    var authUserJson: String?
        get() = securePrefs?.getString("auth_user", null)
        set(value) {
            val sp = securePrefs
            if (sp == null) {
                SendoraCloudLogger.error("Refusing to persist user record — secure storage unavailable")
                return
            }
            val e = sp.edit()
            if (value != null) e.putString("auth_user", value) else e.remove("auth_user")
            e.apply()
        }

    fun clearAuthTokens() {
        securePrefs?.edit()
            ?.remove("auth_access_token")
            ?.remove("auth_access_expires")
            ?.remove("auth_refresh_token")
            ?.remove("auth_user")
            ?.apply()
    }

    fun saveEventQueue(events: List<Map<String, Any?>>) {
        try {
            val jsonArray = JSONArray()
            events.forEach { event ->
                val stripped = event.toMutableMap()
                stripped.remove("userId")
                (stripped["properties"] as? Map<*, *>)?.let { props ->
                    stripped["properties"] = props.filterKeys { it != "traits" }
                }
                jsonArray.put(JSONObject(stripped))
            }
            prefs.edit().putString("event_queue", jsonArray.toString()).apply()
        } catch (e: Exception) {
            SendoraCloudLogger.error("Failed to save event queue", e)
        }
    }

    fun loadEventQueue(): List<Map<String, Any?>> {
        val json = prefs.getString("event_queue", null) ?: return emptyList()
        return try {
            val array = JSONArray(json)
            (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                obj.keys().asSequence().associateWith { key -> obj.get(key) }
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun clearEventQueue() {
        prefs.edit().remove("event_queue").apply()
    }
}
