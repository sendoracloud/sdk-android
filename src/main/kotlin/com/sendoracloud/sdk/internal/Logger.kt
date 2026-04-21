package com.sendoracloud.sdk.internal

import android.util.Log

internal object SendoraCloudLogger {
    var isEnabled = false
    private const val TAG = "SendoraCloud"

    fun debug(message: String) {
        if (isEnabled) Log.d(TAG, message)
    }

    fun error(message: String, throwable: Throwable? = null) {
        if (isEnabled) Log.e(TAG, message, throwable)
    }
}
