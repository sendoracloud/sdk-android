package com.sendoracloud.sdk.internal

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.AEADBadTagException

/**
 * 4.29.0 — an encrypted store restored from Android Auto Backup onto a device whose
 * Keystore holds a different master key. Seen on a real emulator: `EncryptedSharedPreferences.create`
 * threw `AEADBadTagException` (cause: keystore2 VERIFICATION_FAILED) on EVERY launch, so the SDK
 * refused every sign-in (`SecureStorageUnavailable`) and minted a new device id per launch.
 * Driven through the real [Storage] over in-memory prefs; [Disk] stands in for the file + Keystore.
 */
class SecureStoreRecoveryTest {

    /** The `sendora_sdk_secure.xml` file: its entries, and whether this device's master key can open it. */
    private class Disk(var foreignKeyset: Boolean, val entries: MutableMap<String, Any?> = mutableMapOf()) {
        var opens = 0
        var wipes = 0
        fun open(): SharedPreferences {
            opens++
            if (foreignKeyset) throw AEADBadTagException() // what Tink surfaces for a keyset sealed by another key
            return MemoryPrefs(entries)
        }
        fun wipe(): Boolean { wipes++; entries.clear(); foreignKeyset = false; return true }
    }

    private val logs = mutableListOf<String>()
    private fun launch(disk: Disk, plain: MutableMap<String, Any?>): Storage =
        Storage(MemoryPrefs(plain), openSecureStoreWithRecovery(disk::open, disk::wipe) { m, _ -> logs += m })

    @Test
    fun `a restored unreadable store is recreated once - fresh guest, stable device id across later launches`() {
        val disk = Disk(foreignKeyset = true, entries = mutableMapOf(AuthKeys.REFRESH to "sealed-by-the-old-device", "device_id" to "old"))
        val plain = mutableMapOf<String, Any?>()

        val first = launch(disk, plain)
        assertTrue("secure storage works again", first.isSecureAvailable)
        assertNull("no session survives — the old one was undecryptable", first.secureGet(AuthKeys.REFRESH))
        val id = first.deviceId
        assertEquals(1, disk.wipes)
        assertTrue("the recovery is logged", logs.any { "recreating" in it })

        val second = launch(disk, plain)
        val third = launch(disk, plain)
        assertEquals("device id persisted, not ephemeral", id, second.deviceId)
        assertEquals(id, third.deviceId)
        assertEquals("later launches open the recreated store without wiping it", 1, disk.wipes)
    }

    @Test
    fun `the store is recreated at most once - a second failure stays fail-closed`() {
        val disk = object {
            var wipes = 0
            fun open(): SharedPreferences = throw AEADBadTagException()
            fun wipe(): Boolean { wipes++; return true }
        }
        val s = Storage(MemoryPrefs(mutableMapOf()), openSecureStoreWithRecovery(disk::open, disk::wipe) { _, _ -> })
        assertFalse(s.isSecureAvailable)
        assertEquals("ONE delete, no loop", 1, disk.wipes)
    }

    @Test
    fun `a platform failure (not unreadable content) never deletes the store`() {
        for (failure in listOf<Throwable>(java.security.KeyStoreException("keystore busy"), NoClassDefFoundError("androidx/security/crypto/MasterKey"), IllegalStateException("x"))) {
            var wipes = 0
            val r = openSecureStoreWithRecovery<SharedPreferences>({ throw failure }, { wipes++; true }) { _, _ -> }
            assertNull(r)
            assertEquals("${failure.javaClass.simpleName} must not wipe a possibly readable session", 0, wipes)
        }
    }

    @Test
    fun `unreadable content is recognised through wrapping exceptions`() {
        assertTrue(isUnreadableSecureStore(java.security.GeneralSecurityException("decrypt failed", AEADBadTagException())))
        assertTrue(isUnreadableSecureStore(RuntimeException(java.io.IOException(InvalidProtocolBufferException()))))
        assertFalse(isUnreadableSecureStore(java.security.KeyStoreException("busy")))
    }

    @Test
    fun `a healthy store is opened as is`() {
        val disk = Disk(foreignKeyset = false, entries = mutableMapOf("device_id" to "kept"))
        val s = launch(disk, mutableMapOf())
        assertEquals("kept", s.deviceId)
        assertEquals(0, disk.wipes)
    }

    /** Named like protobuf's (Tink shades it), which is all the classifier looks at. */
    private class InvalidProtocolBufferException : java.io.IOException("Protocol message contained an invalid tag")
}

/** An in-memory [SharedPreferences] over a caller-owned map (the "file"). */
internal class MemoryPrefs(private val map: MutableMap<String, Any?>) : SharedPreferences {
    override fun getAll(): MutableMap<String, *> = HashMap(map)
    override fun getString(key: String, defValue: String?): String? = map[key] as? String ?: defValue
    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? = map[key] as? MutableSet<String> ?: defValues
    override fun getInt(key: String, defValue: Int): Int = map[key] as? Int ?: defValue
    override fun getLong(key: String, defValue: Long): Long = map[key] as? Long ?: defValue
    override fun getFloat(key: String, defValue: Float): Float = map[key] as? Float ?: defValue
    override fun getBoolean(key: String, defValue: Boolean): Boolean = map[key] as? Boolean ?: defValue
    override fun contains(key: String): Boolean = map.containsKey(key)
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
        private val puts = mutableMapOf<String, Any?>()
        private val removes = mutableSetOf<String>()
        private var clear = false
        override fun putString(key: String, value: String?) = apply { puts[key] = value }
        override fun putStringSet(key: String, values: MutableSet<String>?) = apply { puts[key] = values }
        override fun putInt(key: String, value: Int) = apply { puts[key] = value }
        override fun putLong(key: String, value: Long) = apply { puts[key] = value }
        override fun putFloat(key: String, value: Float) = apply { puts[key] = value }
        override fun putBoolean(key: String, value: Boolean) = apply { puts[key] = value }
        override fun remove(key: String) = apply { removes += key }
        override fun clear() = apply { clear = true }
        override fun commit(): Boolean { apply(); return true }
        override fun apply() {
            if (clear) map.clear()
            removes.forEach { map.remove(it) }
            puts.forEach { (k, v) -> if (v == null) map.remove(k) else map[k] = v }
        }
    }
}
