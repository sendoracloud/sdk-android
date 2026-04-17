package com.sendora.sdk.internal

import android.util.Log

internal object SendoraLogger {
    var isEnabled = false
    private const val TAG = "Sendora"

    fun debug(message: String) {
        if (isEnabled) Log.d(TAG, message)
    }

    fun error(message: String, throwable: Throwable? = null) {
        if (isEnabled) Log.e(TAG, message, throwable)
    }
}
