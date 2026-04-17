package com.sendora.sdk.internal

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
 *  - `cachedUserId` + `deviceId` live in EncryptedSharedPreferences (AES256-GCM,
 *    key stored in AndroidKeyStore).
 *  - Event queue persisted with `userId` + `traits` stripped — they'll be
 *    re-injected from `currentUserId` at send time.
 */
internal class Storage(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("sendora_sdk", Context.MODE_PRIVATE)

    private val securePrefs: SharedPreferences = runCatching {
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
    }.getOrElse {
        // Fall back to plain prefs if Keystore is unavailable (very rare;
        // typically only on corrupt devices). Data still scoped to our app.
        SendoraLogger.error("EncryptedSharedPreferences unavailable — falling back", it)
        prefs
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
        get() = securePrefs.getString("user_id", null)
        set(value) {
            val e = securePrefs.edit()
            if (value != null) e.putString("user_id", value) else e.remove("user_id")
            e.apply()
        }

    val deviceId: String
        get() = synchronized(_sessionLock) {
            val existing = securePrefs.getString("device_id", null)
            if (existing != null) return existing
            val newId = UUID.randomUUID().toString()
            securePrefs.edit().putString("device_id", newId).apply()
            newId
        }

    fun regenerateDeviceId() {
        securePrefs.edit().remove("device_id").apply()
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
            SendoraLogger.error("Failed to save event queue", e)
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
