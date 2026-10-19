package com.sendoracloud.sdk.internal

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** The encrypted tier's file (frozen name, ADR-023). */
internal const val SECURE_PREFS_NAME = "sendora_sdk_secure"

/**
 * 4.29.0 — is this a failure of the STORE'S CONTENT (a keyset the current master
 * key cannot open), as opposed to the platform (no Keystore, missing AndroidX)?
 * Android Auto Backup restores `sendora_sdk_secure.xml` onto a new device (or a
 * reinstall) whose Keystore holds a different master key: the keyset's MAC fails
 * (`AEADBadTagException`, caused by keystore2 `VERIFICATION_FAILED`). A corrupt
 * keyset blob fails protobuf parsing. Only these are wiped — a transient Keystore
 * error must never delete a readable session.
 */
internal fun isUnreadableSecureStore(t: Throwable): Boolean {
    var c: Throwable? = t
    var depth = 0
    while (c != null && depth++ < 16) {
        if (c is javax.crypto.BadPaddingException) return true // incl. AEADBadTagException
        if (c.javaClass.name.endsWith("InvalidProtocolBufferException")) return true
        c = c.cause
    }
    return false
}

/**
 * 4.29.0 — open the encrypted store; when its CONTENT is unreadable
 * ([isUnreadableSecureStore]) delete it and recreate it ONCE. Before this, an
 * Auto Backup restore left the store permanently unopenable: every launch
 * refused sign-in (`SecureStorageUnavailable`) and minted a new ephemeral
 * device id. Now the device starts as a fresh guest with a persisted, stable
 * device id (the old session was undecryptable anyway — nothing readable is
 * lost). Any other failure, or a second failure, stays fail-closed (null).
 */
internal fun <T : Any> openSecureStoreWithRecovery(
    open: () -> T,
    wipe: () -> Boolean,
    log: (String, Throwable?) -> Unit = { m, t -> SendoraCloudLogger.error(m, t) },
): T? {
    val first = try {
        return open()
    } catch (t: Throwable) {
        t
    }
    if (!isUnreadableSecureStore(first)) {
        log("EncryptedSharedPreferences init failed — auth tokens will not persist. Refusing plaintext fallback.", first)
        return null
    }
    log("EncryptedSharedPreferences unreadable (restored from a backup or a reset Keystore) — deleting and recreating it once; this device starts signed out", first)
    val wiped = try { wipe() } catch (t: Throwable) { log("Could not delete the unreadable secure store", t); false }
    if (!wiped) log("The unreadable secure store may not have been fully deleted — trying to recreate it anyway", null)
    return try {
        open()
    } catch (t: Throwable) {
        log("EncryptedSharedPreferences still unavailable after recreating it — auth tokens will not persist. Refusing plaintext fallback.", t)
        null
    }
}

/**
 * Persistent storage.
 *  - Non-sensitive (`isFirstLaunch`, `sessionId`) lives in plain SharedPreferences.
 *  - `cachedUserId` + `deviceId` + auth tokens live in EncryptedSharedPreferences
 *    (AES256-GCM, key stored in AndroidKeyStore).
 *  - Event queue persisted as it will be sent (s58.405: `userId` is KEPT — see
 *    [saveEventQueue]); the identity token is never written.
 *
 * **Critical:** if EncryptedSharedPreferences cannot be initialised (corrupt
 * Keystore, missing AndroidX dep), token writes are REFUSED rather than
 * silently downgraded to plaintext SharedPreferences. The previous fallback
 * exposed access + refresh tokens in cleartext on disk — full account
 * takeover on rooted devices or via post-uninstall data extraction.
 * 4.29.0: an UNREADABLE store (restored backup) is deleted and recreated once —
 * see [openSecureStoreWithRecovery]. The primary constructor takes the two
 * tiers directly so the JVM suite drives the real class over in-memory prefs.
 */
internal class Storage internal constructor(
    private val prefs: SharedPreferences,
    /**
     * Null when secure storage is unavailable. Every secure getter/setter
     * checks this and refuses the operation if null — token persistence
     * fails closed instead of degrading to plaintext.
     */
    private val securePrefs: SharedPreferences?,
) : AuthStore, EventQueueStore {

    constructor(context: Context) : this(
        context.getSharedPreferences("sendora_sdk", Context.MODE_PRIVATE),
        openSecureStoreWithRecovery(
            open = {
                val master = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()
                EncryptedSharedPreferences.create(
                    context,
                    SECURE_PREFS_NAME,
                    master,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
                )
            },
            // Evicts the in-memory instance too (ContextImpl's prefs cache). The keysets
            // live INSIDE this file, so deleting it is the whole reset. ⚠ The AndroidKeyStore
            // master key is NOT deleted: `_androidx_security_master_key_` is the library's
            // DEFAULT alias, shared with any EncryptedSharedPreferences the host app owns.
            wipe = { context.deleteSharedPreferences(SECURE_PREFS_NAME) },
        ),
    )

    /** True when secure storage is available. Auth.signIn etc. should
     *  surface a configuration error to the consumer if false. */
    override val isSecureAvailable: Boolean get() = securePrefs != null

    /**
     * On-device schema/format-version marker (ADR-023 §5). Non-sensitive →
     * plain SharedPreferences (NOT EncryptedSharedPreferences). Written once
     * at init while the format is still v1, so a future SDK can branch a
     * read-old→write-new migration on it (`if (stored < N) migrate()`)
     * instead of guessing. New key — read nowhere yet; never rename existing
     * keys (frozen per ADR-023 §3.4).
     */
    fun ensureSchemaVersion() {
        if (!prefs.contains(AuthKeys.SCHEMA_VERSION)) {
            prefs.edit().putString(AuthKeys.SCHEMA_VERSION, AuthKeys.SCHEMA_VERSION_V1).apply()
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

    // --- Auth Service material (EncryptedSharedPreferences ONLY) ---
    //
    // ADR-033 wave 1: the auth machine writes through the [AuthStore] seam
    // below, naming keys only via [AuthKeys] (INV-1). The typed properties that
    // follow are thin wrappers kept for the other modules (`cachedUserId` is
    // the analytics id, not auth material, and stays above).

    override fun secureGet(key: String): String? = securePrefs?.getString(key, null)

    override fun securePut(key: String, value: String?) {
        val sp = securePrefs
        if (sp == null) {
            // Fail CLOSED: never downgrade a token to the plaintext tier.
            SendoraCloudLogger.error("Refusing to persist $key — secure storage unavailable")
            return
        }
        val e = sp.edit()
        if (value != null) e.putString(key, value) else e.remove(key)
        e.apply()
    }

    override fun secureGetLong(key: String): Long = securePrefs?.getLong(key, 0L) ?: 0L

    override fun securePutLong(key: String, value: Long) {
        val sp = securePrefs ?: return
        val e = sp.edit()
        if (value > 0) e.putLong(key, value) else e.remove(key)
        e.apply()
    }

    override fun plainGet(key: String): String? = prefs.getString(key, null)

    override fun plainPut(key: String, value: String?) {
        val e = prefs.edit()
        if (value != null) e.putString(key, value) else e.remove(key)
        e.apply()
    }

    /** Synchronous read of the cached access token (the frozen `auth_access_token` key). */
    val authAccessToken: String? get() = secureGet(AuthKeys.ACCESS)

    val authRefreshToken: String? get() = secureGet(AuthKeys.REFRESH)

    /** Unix-millis when the cached access token expires. 0 = unknown. */
    val authAccessExpiresAt: Long get() = secureGetLong(AuthKeys.EXPIRES)

    /** JSON-encoded `AuthUser`. Decoded by SendoraCloudAuth. */
    val authUserJson: String? get() = secureGet(AuthKeys.USER)

    /**
     * ⚠ s58.405: this used to strip `userId` (and a `properties.traits` key), claiming they would be
     * "re-injected from `currentUserId` at send time" — nothing ever did, and the user at send time is not
     * necessarily the one who produced the event. An identified event carries `userId` INSTEAD of
     * `anonymousId` (`buildEventPayload`), so a restored event went out with NEITHER (unattributed) and could
     * never get its send-time identity token (`decorateWithIdentity` matches on `userId`). The strip never
     * covered `identify()`'s traits either: they are the `properties` of `user.identified`. The identity token
     * is never stored (attached at send time only; removed here as a belt). Backward compatible: a queue
     * written by ≤ 4.29.0 has no `userId`, which reads back as absent — exactly what those builds sent.
     */
    override fun saveEventQueue(events: List<Map<String, Any?>>) {
        try {
            val jsonArray = JSONArray()
            events.forEach { event ->
                jsonArray.put(JSONObject(if (event.containsKey("identityToken")) event - "identityToken" else event))
            }
            prefs.edit().putString("event_queue", jsonArray.toString()).apply()
        } catch (e: Exception) {
            SendoraCloudLogger.error("Failed to save event queue", e)
        }
    }

    override fun loadEventQueue(): List<Map<String, Any?>> {
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

    override fun clearEventQueue() {
        prefs.edit().remove("event_queue").apply()
    }

    /**
     * 4.28.0 — per-event attempt counts, a JSON int array parallel to the
     * frozen `event_queue` (ADR-023: additive key, the queue's own format is
     * unchanged; a 4.27.0 simply never reads it). Plain tier: counts only.
     */
    override fun loadEventAttempts(): List<Int> {
        val json = prefs.getString(EVENT_QUEUE_ATTEMPTS_KEY, null) ?: return emptyList()
        return try {
            val array = JSONArray(json)
            (0 until array.length()).map { i -> array.optInt(i, 0) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    override fun saveEventAttempts(attempts: List<Int>) {
        val e = prefs.edit()
        if (attempts.isEmpty()) e.remove(EVENT_QUEUE_ATTEMPTS_KEY) else e.putString(EVENT_QUEUE_ATTEMPTS_KEY, JSONArray(attempts).toString())
        e.apply()
    }

    private companion object {
        const val EVENT_QUEUE_ATTEMPTS_KEY = "event_queue_attempts"
    }
}
