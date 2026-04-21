package com.sendoracloud.sdk

sealed class SendoraError(message: String) : IllegalArgumentException("[SendoraCloud] $message") {
    class InvalidApiKey(msg: String) : SendoraError(msg)
    class InvalidApiUrl(msg: String) : SendoraError(msg)
    class InvalidEventName(name: String) : SendoraError("invalid event name: $name")
    class PayloadTooLarge(bytes: Int) : SendoraError("payload too large: $bytes bytes")
    class PayloadTooDeep(depth: Int) : SendoraError("payload nested too deep: $depth levels")
    class ForbiddenKey(key: String) : SendoraError("forbidden property key: $key")
}

internal object SendoraCloudValidator {
    private val keyRegex = Regex("^pk_[A-Za-z0-9_-]{16,}$")
    private val eventRegex = Regex("^[a-zA-Z][a-zA-Z0-9._:\\-]{0,127}$")
    private const val MAX_BYTES = 32 * 1024
    private const val MAX_DEPTH = 5
    private val forbidden = setOf("__proto__", "constructor", "prototype")

    fun validateApiKey(key: String) {
        if (key.startsWith("sk_") || key.startsWith("sendora_secret_")) {
            throw SendoraError.InvalidApiKey(
                "secret keys cannot be used in Android SDK — use a publishable key (pk_...)"
            )
        }
        if (!keyRegex.matches(key)) {
            throw SendoraError.InvalidApiKey("expected pk_... (17+ chars)")
        }
    }

    fun validateApiUrl(url: String) {
        if (url.startsWith("http://localhost") || url.startsWith("http://10.0.2.2") ||
            url.startsWith("http://127.0.0.1")) return
        if (!url.startsWith("https://")) {
            throw SendoraError.InvalidApiUrl("must be https:// (http://localhost or 10.0.2.2 ok in dev)")
        }
    }

    fun validateEventName(name: String) {
        if (!eventRegex.matches(name)) throw SendoraError.InvalidEventName(name)
    }

    fun validateProperties(props: Map<String, Any?>?) {
        if (props == null) return
        assertNoForbidden(props)
        val depth = measureDepth(props)
        if (depth > MAX_DEPTH) throw SendoraError.PayloadTooDeep(depth)
        val size = org.json.JSONObject(props).toString().length
        if (size > MAX_BYTES) throw SendoraError.PayloadTooLarge(size)
    }

    private fun assertNoForbidden(v: Any?) {
        when (v) {
            is Map<*, *> -> for ((k, value) in v) {
                if (k is String && k in forbidden) throw SendoraError.ForbiddenKey(k)
                assertNoForbidden(value)
            }
            is List<*> -> for (value in v) assertNoForbidden(value)
        }
    }

    private fun measureDepth(v: Any?, depth: Int = 0): Int = when (v) {
        is Map<*, *> -> v.values.maxOfOrNull { measureDepth(it, depth + 1) } ?: depth
        is List<*> -> v.maxOfOrNull { measureDepth(it, depth + 1) } ?: depth
        else -> depth
    }
}
