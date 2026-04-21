package com.sendoracloud.sdk.internal

import java.security.MessageDigest

internal object FingerprintGenerator {
    fun generate(device: DeviceContext): String {
        val input = listOf(
            device.model,
            device.osVersion,
            device.screenWidth.toString(),
            device.screenHeight.toString(),
            device.locale,
            device.timezone,
        ).joinToString("|")

        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.take(16).joinToString("") { "%02x".format(it) }
    }
}
