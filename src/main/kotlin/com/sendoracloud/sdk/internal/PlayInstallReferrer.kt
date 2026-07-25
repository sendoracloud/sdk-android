package com.sendoracloud.sdk.internal

import android.content.Context
import com.android.installreferrer.api.InstallReferrerClient
import com.android.installreferrer.api.InstallReferrerStateListener
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Wave 51 — Play Install Referrer helper.
 *
 * Wraps Google Play's [InstallReferrerClient] in a coroutine-friendly API.
 * Returns the URL-encoded referrer string + Play-reported timestamps the
 * backend's `/attribution/install-referrer` endpoint consumes.
 *
 * The `com.android.installreferrer:installreferrer` dependency is
 * declared `compileOnly` on the SDK so host apps opt-in. Callers MUST
 * guard usage with [isAvailable] — a host app without the dep will hit
 * `NoClassDefFoundError` on first SDK use otherwise.
 */
internal data class PlayInstallReferrerResult(
    val referrer: String,
    val referrerClickAtMs: Long,
    val installBeginAtMs: Long,
    val googlePlayInstant: Boolean,
)

internal object PlayInstallReferrer {
    /**
     * Returns true when the host app shipped
     * `com.android.installreferrer:installreferrer`. Cheap class-lookup;
     * cached after first call.
     */
    @Volatile private var availableCache: Boolean? = null

    fun isAvailable(): Boolean {
        availableCache?.let { return it }
        return try {
            Class.forName("com.android.installreferrer.api.InstallReferrerClient")
            true.also { availableCache = it }
        } catch (_: Throwable) {
            false.also { availableCache = it }
        }
    }

    /**
     * Connect to the Play Install Referrer service and read the referrer
     * once. Resolves to `null` when the service is unavailable, the
     * dep is missing, or Play returns a non-OK status — in every case
     * the caller falls back to the standard `/attribution/install`
     * path so attribution still records.
     *
     * Cancellable: if the coroutine is cancelled before the listener
     * fires, we end the underlying connection so the binder doesn't leak.
     */
    suspend fun fetch(context: Context): PlayInstallReferrerResult? {
        if (!isAvailable()) return null
        return try {
            suspendCancellableCoroutine { cont ->
                val client = InstallReferrerClient.newBuilder(context.applicationContext).build()
                cont.invokeOnCancellation { runCatching { client.endConnection() } }
                client.startConnection(object : InstallReferrerStateListener {
                    override fun onInstallReferrerSetupFinished(responseCode: Int) {
                        try {
                            if (responseCode != InstallReferrerClient.InstallReferrerResponse.OK) {
                                cont.resume(null)
                                return
                            }
                            val details = client.installReferrer
                            cont.resume(
                                PlayInstallReferrerResult(
                                    referrer = details.installReferrer ?: "",
                                    referrerClickAtMs = details.referrerClickTimestampSeconds * 1000L,
                                    installBeginAtMs = details.installBeginTimestampSeconds * 1000L,
                                    googlePlayInstant = details.googlePlayInstantParam,
                                ),
                            )
                        } catch (_: Throwable) {
                            cont.resume(null)
                        } finally {
                            runCatching { client.endConnection() }
                        }
                    }

                    override fun onInstallReferrerServiceDisconnected() {
                        // Connection dropped before result — treat as no referrer.
                        if (cont.isActive) cont.resume(null)
                    }
                })
            }
        } catch (_: Throwable) {
            null
        }
    }
}
