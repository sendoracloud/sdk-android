package com.sendora.sdk.internal

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * HTTPS-only client with exponential backoff + circuit breaker.
 * Never throws — errors log and the call returns null.
 */
internal class ApiClient(
    baseUrl: String,
    private val apiKey: String,
) {
    private val baseUrl: String = baseUrl.trimEnd('/')
    private val consecutiveFailures = AtomicInteger(0)
    private val nextAllowedAfter = AtomicLong(0)

    private val maxFailures = 10
    private val maxBackoffMs = 60_000L

    suspend fun post(path: String, body: Map<String, Any?>): Map<String, Any?>? {
        if (shouldSkip()) return null
        return withTimeoutOrNull(10_000L) {
            withContext(Dispatchers.IO) { postInternal(path, body) }
        }
    }

    suspend fun postBatch(path: String, events: List<Map<String, Any?>>): Boolean {
        val response = post(path, mapOf("events" to events))
        return (response?.get("success") as? Boolean) == true
    }

    private fun postInternal(path: String, body: Map<String, Any?>): Map<String, Any?>? {
        val fullUrl = "$baseUrl/api/v1$path"
        if (!fullUrl.startsWith("https://") &&
            !fullUrl.startsWith("http://localhost") &&
            !fullUrl.startsWith("http://10.0.2.2") &&
            !fullUrl.startsWith("http://127.0.0.1")) {
            SendoraLogger.error("ApiClient refusing non-HTTPS URL")
            return null
        }
        return try {
            val conn = URL(fullUrl).openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-API-Key", apiKey)
            conn.setRequestProperty("Connection", "close")
            conn.connectTimeout = 5_000
            conn.readTimeout = 5_000
            conn.doOutput = true
            val jsonBody = JSONObject(body).toString()
            OutputStreamWriter(conn.outputStream).use { it.write(jsonBody) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val response = BufferedReader(InputStreamReader(stream)).use { it.readText() }
            if (code !in 200..299) {
                recordFailure()
                null
            } else {
                recordSuccess()
                val json = JSONObject(response)
                json.keys().asSequence().associateWith { key -> json.get(key) }
            }
        } catch (e: Exception) {
            SendoraLogger.debug("API error ($path): ${e.message}")
            recordFailure()
            null
        }
    }

    private fun shouldSkip(): Boolean {
        if (consecutiveFailures.get() > maxFailures) return true
        return System.currentTimeMillis() < nextAllowedAfter.get()
    }

    private fun recordSuccess() {
        consecutiveFailures.set(0)
        nextAllowedAfter.set(0)
    }

    private fun recordFailure() {
        val n = consecutiveFailures.incrementAndGet()
        val delay = minOf(maxBackoffMs, (1L shl n.coerceAtMost(20)) * 1000L)
        nextAllowedAfter.set(System.currentTimeMillis() + delay)
    }
}
