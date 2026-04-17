package com.sendora.sdk

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.sendora.sdk.internal.*
import kotlinx.coroutines.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

/**
 * Sendora Android SDK — deep linking, attribution, event tracking.
 *
 * Security
 *  - Secret (`sk_`) keys are refused at init.
 *  - `apiBaseUrl` must be HTTPS (localhost and 10.0.2.2 allowed in dev).
 *  - `handleDeepLink` accepts only URIs whose host is in `config.linkHosts`.
 *  - `identify` accepts an HMAC `identityToken` to block spoofing.
 *  - User ID + device ID live in `EncryptedSharedPreferences`. Event queue
 *    on disk is PII-stripped.
 */
object Sendora {
    private var config: SendoraConfig? = null
    private var apiClient: ApiClient? = null
    private var storage: Storage? = null
    private var eventQueue: EventQueue? = null
    private var deviceContext: DeviceContext? = null
    private var fingerprintHash: String? = null
    private var currentUserId: String? = null
    private var currentIdentityToken: String? = null
    private var isConfigured = false

    /** Consent gate. Events queue but do not send until granted. */
    val consent: SendoraConsent = SendoraConsent(false)

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob() + CoroutineExceptionHandler { _, e ->
        SendoraLogger.error("Coroutine error", e)
    })

    private val isoFormatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    /** Initialize. Call once from Application.onCreate. */
    fun init(context: Context, apiKey: String, projectId: String, options: SendoraConfig? = null) {
        val appContext = context.applicationContext
        val cfg = options ?: SendoraConfig(apiKey = apiKey, projectId = projectId)
        val finalConfig = cfg.copy(
            apiKey = cfg.apiKey.ifEmpty { apiKey },
            projectId = cfg.projectId.ifEmpty { projectId },
        )

        try {
            SendoraValidator.validateApiKey(finalConfig.apiKey)
            SendoraValidator.validateApiUrl(finalConfig.apiBaseUrl)
        } catch (e: SendoraError) {
            SendoraLogger.error(e.message ?: "invalid config")
            return
        }

        config = finalConfig
        SendoraLogger.isEnabled = finalConfig.debug

        if (finalConfig.defaultConsent) consent.grant()

        val store = Storage(appContext)
        storage = store
        currentUserId = store.cachedUserId

        val device = DeviceContext.collect(appContext)
        deviceContext = device
        fingerprintHash = FingerprintGenerator.generate(device)

        val client = ApiClient(finalConfig.apiBaseUrl, finalConfig.apiKey)
        apiClient = client

        val queue = EventQueue(store, finalConfig.flushAt, finalConfig.maxQueueSize)
        queue.setFlushHandler { events ->
            if (!consent.isGranted) return@setFlushHandler
            flushEvents(events, client)
        }
        queue.startTimer(finalConfig.flushInterval)
        eventQueue = queue

        isConfigured = true
        consent.subscribe { granted ->
            if (granted) scope.launch { eventQueue?.flush() }
        }

        SendoraLogger.debug("Configured — project: $projectId")

        if (finalConfig.autoStartAttribution) {
            scope.launch {
                reportInstallIfNeeded()
                trackSessionStart()
            }
        }

        runCatching {
            ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
                override fun onStop(owner: LifecycleOwner) {
                    scope.launch {
                        eventQueue?.persistToDisk()
                        trackSessionEnd()
                    }
                }
            })
        }
    }

    /** Start install reporting + session tracking. Call this after your
     *  consent prompt when `autoStartAttribution = false`. */
    fun startAttribution() {
        if (!isConfigured) return
        scope.launch {
            reportInstallIfNeeded()
            trackSessionStart()
        }
    }

    fun handleDeepLink(intent: Intent): SendoraLinkData? {
        if (!isConfigured) return null
        val uri = intent.data ?: return null
        return parseDeepLink(uri)
    }

    fun handleDeepLink(uri: Uri): SendoraLinkData? {
        if (!isConfigured) return null
        return parseDeepLink(uri)
    }

    fun checkDeferredDeepLink(callback: (SendoraLinkData?) -> Unit) {
        val cfg = config
        val store = storage
        val client = apiClient
        if (!isConfigured || cfg == null || store == null || client == null || !store.isFirstLaunch) {
            callback(null); return
        }
        scope.launch {
            val body = mutableMapOf<String, Any?>("projectId" to cfg.projectId)
            fingerprintHash?.let { body["fingerprintHash"] = it }
            body["deviceId"] = store.deviceId
            val response = client.post("/attribution/deferred", body)
            val data = (response?.get("data") as? Map<*, *>)
            val found = data?.get("found") as? Boolean ?: false
            withContext(Dispatchers.Main) {
                if (found) {
                    callback(SendoraLinkData(
                        shortcode = "",
                        deepLinkPath = data?.get("deepLinkPath") as? String,
                        campaign = data?.get("campaign") as? String,
                        source = data?.get("source") as? String,
                        medium = data?.get("medium") as? String,
                        @Suppress("UNCHECKED_CAST")
                        linkData = (data?.get("deepLinkData") as? Map<String, Any>) ?: emptyMap(),
                    ))
                } else {
                    callback(null)
                }
            }
        }
    }

    fun trackEvent(name: String, properties: Map<String, Any>? = null) {
        if (!isConfigured) return
        val cfg = config ?: return
        try {
            SendoraValidator.validateEventName(name)
            SendoraValidator.validateProperties(properties)
        } catch (e: SendoraError) {
            SendoraLogger.error(e.message ?: "invalid event")
            return
        }

        val event = buildMap<String, Any?> {
            put("projectId", cfg.projectId)
            put("module", "custom")
            put("eventType", name)
            put("timestamp", isoFormatter.format(Date()))
            put("properties", properties ?: emptyMap<String, Any>())
            put("context", mapOf(
                "device" to (deviceContext?.toMap() ?: emptyMap()),
                "sdk" to mapOf("name" to "sendora-android", "version" to "1.0.0"),
            ))
            put("sessionId", storage?.sessionId ?: "")
            put("consent", listOf("analytics"))
            currentUserId?.let { put("userId", it) }
            currentIdentityToken?.let { put("identityToken", it) }
        }
        scope.launch { eventQueue?.add(event) }
    }

    fun identify(userId: String, traits: Map<String, Any>? = null, options: SendoraIdentifyOptions? = null) {
        if (!isConfigured) return
        if (userId.isEmpty() || userId.length > 256) {
            SendoraLogger.error("userId must be 1-256 chars")
            return
        }
        currentUserId = userId
        currentIdentityToken = options?.identityToken
        storage?.cachedUserId = userId
        trackEvent("user.identified", traits ?: emptyMap())
    }

    fun reset() {
        if (!isConfigured) return
        currentUserId = null
        currentIdentityToken = null
        storage?.cachedUserId = null
        storage?.regenerateDeviceId()
        storage?.sessionId = UUID.randomUUID().toString()
    }

    // --- Private ---

    private fun parseDeepLink(uri: Uri): SendoraLinkData? {
        val cfg = config ?: return null
        val host = uri.host?.lowercase() ?: return null
        val allowed = cfg.linkHosts.any { host == it || host.endsWith(".$it") }
        if (!allowed) return null

        val segments = uri.pathSegments ?: return null
        val shortcode = when {
            segments.size >= 2 && segments[0] == "link" -> segments[1]
            segments.size == 1 -> segments[0]
            else -> return null
        }
        if (shortcode.isEmpty() || shortcode.length > 40) return null
        if (!shortcode.matches(Regex("^[A-Za-z0-9_-]+$"))) return null

        trackEvent("links.opened", mapOf("shortcode" to shortcode))
        return SendoraLinkData(shortcode = shortcode)
    }

    private suspend fun reportInstallIfNeeded() {
        val store = storage ?: return
        if (!store.isFirstLaunch) return
        val client = apiClient ?: return
        val cfg = config ?: return
        store.isFirstLaunch = false
        val body = mapOf<String, Any?>(
            "projectId" to cfg.projectId,
            "deviceId" to store.deviceId,
            "fingerprintHash" to (fingerprintHash ?: ""),
            "appVersion" to (deviceContext?.appVersion ?: ""),
            "os" to "Android",
            "osVersion" to (deviceContext?.osVersion ?: ""),
        )
        client.post("/attribution/install", body)
    }

    private fun trackSessionStart() {
        val newSession = UUID.randomUUID().toString()
        storage?.sessionId = newSession
        trackEvent("session.started", mapOf("sessionId" to newSession))
    }

    private fun trackSessionEnd() {
        trackEvent("session.ended", mapOf("sessionId" to (storage?.sessionId ?: "")))
    }

    private fun flushEvents(events: List<Map<String, Any?>>, client: ApiClient) {
        if (events.isEmpty()) return
        scope.launch {
            if (events.size == 1) client.post("/events", events.first())
            else client.postBatch("/events/batch", events)
        }
    }
}
