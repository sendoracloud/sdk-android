package com.sendoracloud.sdk

import android.content.Intent
import com.sendoracloud.sdk.internal.ApiClient
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * 4.29.0 — `play-services-location` is `compileOnly`, so it is absent from this test's runtime
 * classpath exactly as from an app that did not add it. Before the probe, `handleBroadcast` threw
 * `NoClassDefFoundError` into the caller (as did `stop`, and `refresh` from an unhandled coroutine).
 */
class GeofenceOptionalDepTest {
    @Test
    fun `without play-services-location the geofence calls are safe no-ops`() {
        assertFalse("the probe sees the library is absent", SendoraCloudGeofences.isLocationAvailable("test"))
        val g = SendoraCloudGeofences(ApiClient("https://api-dev.sendoracloud.com", "pk_test"), { null }, { null }, { null })
        assertFalse("handleBroadcast answers false instead of throwing", g.handleBroadcast(Intent()))
    }
}
