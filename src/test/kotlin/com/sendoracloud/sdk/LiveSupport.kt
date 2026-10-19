package com.sendoracloud.sdk

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/**
 * Shared by the two live suites (`LiveLifecycleTest`, `LiveStagingTest`) —
 * the host / key guard and the live-run result file
 * (`scripts/e2e/live-run-contract.mjs`, contract 2).
 *
 * ⚠ Nothing here ever prints, logs or writes a key, token or address: the
 * result file carries `detail` evidence only, and [LiveReport.scrub] removes
 * anything shaped like a credential or an email before it is written.
 */
internal object LiveEnv {
    /** The ONLY host a live run may target (`--env dev`, ADR-017). */
    const val STAGING_HOST = "api-dev.sendoracloud.com"

    val enabled: Boolean get() = System.getenv("SENDORA_LIVE") == "1"

    /** `SENDORA_API` (default the staging URL), refused unless its host is [STAGING_HOST]. */
    val api: String by lazy {
        val raw = (System.getenv("SENDORA_API")?.takeIf { it.isNotBlank() } ?: "https://$STAGING_HOST").trimEnd('/')
        val uri = URI(raw)
        require(uri.scheme == "https" && uri.host == STAGING_HOST) { "SENDORA_API must be https://$STAGING_HOST (got host ${uri.host})" }
        raw
    }

    val apiHost: String get() = URI(api).host

    private fun isProd(k: String) = Regex("^(pk|sk)_(prod|live)_").containsMatchIn(k)

    /** `SENDORA_PK` — a staging publishable key. Only its SHAPE is ever reported. */
    val key: String by lazy {
        val k = System.getenv("SENDORA_PK") ?: ""
        require(!isProd(k)) { "refusing a production key" }
        require(k.startsWith("pk_")) { "SENDORA_PK must be a staging publishable (pk_) key" }
        k
    }

    /** `SENDORA_LOG_AUTH` — sent as `x-api-key` (sk_/pk_) or a Bearer session; null when unset. */
    val logAuth: String? by lazy {
        val k = System.getenv("SENDORA_LOG_AUTH")?.takeIf { it.isNotBlank() } ?: return@lazy null
        require(!isProd(k)) { "refusing a production secret key" }
        k
    }
}

/**
 * The live-run result file. Both suites (re)write it after EVERY step, merging
 * by step id with what is already there (same nonce) — so the suites can run in
 * any order, in one JVM or two, and a crash still leaves what was proven.
 */
internal object LiveReport {
    private val lock = Any()

    /** The version string READ FROM THE SDK at runtime (`internal/SdkVersion.kt`), never a literal here. */
    val sdkReportedVersion: String by lazy {
        runCatching {
            Class.forName("com.sendoracloud.sdk.internal.SdkVersionKt").getField("SDK_VERSION").get(null) as String
        }.getOrElse { com.sendoracloud.sdk.internal.SDK_VERSION }
    }

    private val SCRUB = listOf(
        Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}") to "<email>",
        Regex("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*") to "<jwt>",
        Regex("\\b(pk|sk)_[A-Za-z]+_[A-Za-z0-9_-]+") to "<key>",
        Regex("\\bkdt1\\.[A-Za-z0-9_-]+") to "<kdt>",
        Regex("\\blrt_[A-Za-z0-9_-]+") to "<lrt>",
    )

    fun scrub(s: String): String = SCRUB.fold(s) { acc, (re, sub) -> re.replace(acc, sub) }.take(2_000)

    fun record(id: String, pass: Boolean, detail: String, suite: String) {
        val line = "LIVE ${if (pass) "PASS" else "FAIL"} $id — ${scrub(detail)}"
        println(line)
        val path = System.getenv("SENDORA_LIVE_RESULT")?.takeIf { it.isNotBlank() } ?: return
        synchronized(lock) {
            val file = File(path)
            val nonce = System.getenv("SENDORA_LIVE_NONCE") ?: ""
            val existing = runCatching { JSONObject(file.readText()) }.getOrNull()
                ?.takeIf { it.optString("nonce") == nonce && it.optString("sdk") == "android" }
            val steps = linkedMapOf<String, JSONObject>()
            existing?.optJSONArray("steps")?.let { arr ->
                for (i in 0 until arr.length()) arr.optJSONObject(i)?.let { s -> steps[s.optString("id")] = s }
            }
            steps[id] = JSONObject().put("id", id).put("status", if (pass) "pass" else "fail").put("detail", scrub(detail))
            val suites = (existing?.optString("suite")?.split("+")?.filter { it.isNotBlank() } ?: emptyList()).toMutableSet()
            suites += suite
            val out = JSONObject()
                .put("contract", 2)
                .put("nonce", nonce)
                .put("sdk", "android")
                .put("sdkReportedVersion", sdkReportedVersion)
                .put("suite", suites.sorted().joinToString("+"))
                .put("apiHost", LiveEnv.apiHost)
                .put("steps", JSONArray(steps.values.toList()))
            file.parentFile?.mkdirs()
            val tmp = File(file.path + ".tmp")
            tmp.writeText(out.toString(2))
            if (!tmp.renameTo(file)) { file.writeText(out.toString(2)); tmp.delete() }
        }
    }
}

/** A raw request (no SDK code) for staging the scene and reading the server's own verdict. */
internal object LiveHttp {
    data class Res(val status: Int, val body: JSONObject, val retryAfter: String?)

    fun call(method: String, path: String, json: Any? = null, bearer: String? = null, headers: Map<String, String> = emptyMap(), apiKey: String? = LiveEnv.key): Res {
        val conn = URL("${LiveEnv.api}/api/v1$path").openConnection() as HttpURLConnection
        conn.requestMethod = method
        conn.setRequestProperty("Content-Type", "application/json")
        apiKey?.let { conn.setRequestProperty("X-API-Key", it) }
        bearer?.let { conn.setRequestProperty("Authorization", "Bearer $it") }
        headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
        conn.connectTimeout = 10_000; conn.readTimeout = 15_000
        if (json != null) {
            conn.doOutput = true
            OutputStreamWriter(conn.outputStream).use { it.write(json.toString()) }
        }
        val code = conn.responseCode
        val stream = if (code in 200..299) conn.inputStream else conn.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
        return Res(code, runCatching { JSONObject(text) }.getOrDefault(JSONObject()), conn.getHeaderField("Retry-After"))
    }

    fun data(r: Res): JSONObject = r.body.optJSONObject("data") ?: JSONObject()
    fun tokens(r: Res): JSONObject = data(r).optJSONObject("tokens") ?: JSONObject()
    fun err(r: Res): JSONObject = r.body.optJSONObject("error") ?: JSONObject()

    /** The JWT payload (unsigned read — evidence only). */
    fun claims(jwt: String?): JSONObject = runCatching {
        JSONObject(String(java.util.Base64.getUrlDecoder().decode(jwt!!.split(".")[1])))
    }.getOrDefault(JSONObject())
}
