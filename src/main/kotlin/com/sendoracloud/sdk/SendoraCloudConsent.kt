package com.sendoracloud.sdk

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/** Per-purpose consent state. Events buffer until `grant()` is called. */
class SendoraCloudConsent internal constructor(initial: Boolean) {
    private val granted = AtomicBoolean(initial)
    private val listeners = CopyOnWriteArrayList<(Boolean) -> Unit>()

    val isGranted: Boolean get() = granted.get()

    fun grant() = set(true)
    fun revoke() = set(false)

    internal fun subscribe(cb: (Boolean) -> Unit) { listeners.add(cb) }

    private fun set(value: Boolean) {
        if (!granted.compareAndSet(!value, value)) return
        for (cb in listeners) runCatching { cb(value) }
    }
}
