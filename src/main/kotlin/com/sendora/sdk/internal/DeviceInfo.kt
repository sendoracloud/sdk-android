package com.sendora.sdk.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.DisplayMetrics

internal data class DeviceContext(
    val deviceType: String,
    val os: String,
    val osVersion: String,
    val model: String,
    val screenWidth: Int,
    val screenHeight: Int,
    val locale: String,
    val timezone: String,
    val appVersion: String,
) {
    fun toMap(): Map<String, Any> = mapOf(
        "type" to deviceType,
        "os" to os,
        "osVersion" to osVersion,
        "model" to model,
    )

    companion object {
        fun collect(context: Context): DeviceContext {
            val metrics = context.resources.displayMetrics
            val appVersion = try {
                context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "unknown"
            } catch (e: PackageManager.NameNotFoundException) {
                "unknown"
            }

            return DeviceContext(
                deviceType = if (metrics.densityDpi >= DisplayMetrics.DENSITY_MEDIUM &&
                    (metrics.widthPixels / metrics.density) >= 600) "tablet" else "mobile",
                os = "Android",
                osVersion = Build.VERSION.RELEASE,
                model = "${Build.MANUFACTURER} ${Build.MODEL}",
                screenWidth = metrics.widthPixels,
                screenHeight = metrics.heightPixels,
                locale = java.util.Locale.getDefault().toString(),
                timezone = java.util.TimeZone.getDefault().id,
                appVersion = appVersion,
            )
        }
    }
}
