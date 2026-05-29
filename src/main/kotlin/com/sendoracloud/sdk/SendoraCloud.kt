package com.sendoracloud.sdk

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.sendoracloud.sdk.internal.*
import kotlinx.coroutines.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

/**
 * SendoraCloud Android SDK — deep linking, attribution, event tracking.
 *
 * Key format: `pk_prod_*`, `pk_staging_*`, `pk_dev_*` — the key's env
 * is server-enforced on ingest (ADR-014). Legacy `pk_live_*` keys are
 * still accepted and treated as prod for backward compat.
 *
 * Security
 *  - Secret (`sk_`) keys are refused at init.
 *  - `apiBaseUrl` must be HTTPS (localhost and 10.0.2.2 allowed in dev).
 *  - `handleDeepLink` accepts only URIs whose host is in `config.linkHosts`.
 *  - `identify` accepts an HMAC `identityToken` to block spoofing.
 *  - User ID + device ID live in `EncryptedSharedPreferences`. Event queue
 *    on disk is PII-stripped.
 */
object SendoraCloud {
    private var config: SendoraCloudConfig? = null
    private var apiClient: ApiClient? = null
    private var storage: Storage? = null
    private var eventQueue: EventQueue? = null
    private var deviceContext: DeviceContext? = null
    private var fingerprintHash: String? = null
    private var currentUserId: String? = null
    private var currentIdentityToken: String? = null
    private var isConfigured = false

    /** Consent gate. Events queue but do not send until granted. */
    val consent: SendoraCloudConsent = SendoraCloudConsent(false)

    /** Auth Service surface. Initialised in `init()`. */
    var auth: SendoraCloudAuth? = null
        private set

    /** Live updates / persistent notifications via FCM data-only (API 26+). Initialised in `init()`. */
    var liveActivities: SendoraCloudLiveActivities? = null
        private set

    /** Server-managed geofences via GeofencingClient. Initialised in `init()`. */
    var geofences: SendoraCloudGeofences? = null
        private set

    /** Generic push-token registration + open tracking. Initialised in `init()`. */
    var push: SendoraCloudPush? = null
        private set

    /** Deep-link surface: create + handleAppLink + matchDeferred. Initialised in `init()`. */
    var links: SendoraCloudLinks? = null
        private set

    /** Passkeys (WebAuthn via Credential Manager). API 28+ at runtime. */
    val passkeys: SendoraCloudPasskeys?
        get() = auth?.passkeys

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob() + CoroutineExceptionHandler { _, e ->
        SendoraCloudLogger.error("Coroutine error", e)
    })

    private val isoFormatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    /**
     * Initialize. Call once from Application.onCreate.
     *
     * 3.0.0: `projectId` is now optional. When omitted the backend
     * derives project + org + environment from the API key row.
     * Existing callers passing a value continue to work unchanged.
     */
    fun init(context: Context, apiKey: String, projectId: String? = null, options: SendoraCloudConfig? = null) {
        val appContext = context.applicationContext
        val cfg = options ?: SendoraCloudConfig(apiKey = apiKey, projectId = projectId)
        val finalConfig = cfg.copy(
            apiKey = cfg.apiKey.ifEmpty { apiKey },
            projectId = cfg.projectId ?: projectId,
        )

        try {
            SendoraCloudValidator.validateApiKey(finalConfig.apiKey)
            SendoraCloudValidator.validateApiUrl(finalConfig.apiBaseUrl)
        } catch (e: SendoraError) {
            SendoraCloudLogger.error(e.message ?: "invalid config")
            return
        }

        config = finalConfig
        SendoraCloudLogger.isEnabled = finalConfig.debug

        if (finalConfig.defaultConsent) consent.grant()

        val store = Storage(appContext)
        storage = store
        currentUserId = store.cachedUserId

        val device = DeviceContext.collect(appContext)
        deviceContext = device
        fingerprintHash = FingerprintGenerator.generate(device)

        val client = ApiClient(finalConfig.apiBaseUrl, finalConfig.apiKey, finalConfig.pinnedSPKIHashes)
        apiClient = client

        val queue = EventQueue(store, finalConfig.flushAt, finalConfig.maxQueueSize)
        queue.setFlushHandler { events ->
            if (!consent.isGranted) return@setFlushHandler
            flushEvents(events, client)
        }
        queue.startTimer(finalConfig.flushInterval)
        eventQueue = queue

        auth = SendoraCloudAuth(
            client = client,
            storage = store,
            onIdentityChange = { userId ->
                currentUserId = userId
                store.cachedUserId = userId
            },
            onAnonymousWipe = {
                // Switching identities — rotate device-side state so
                // events from the new user can't carry over the prior
                // anonymous attribution. Also drain the event queue:
                // pending events were captured under the prior
                // currentUserId and shouldn't surface under the next.
                currentUserId = null
                currentIdentityToken = null
                store.cachedUserId = null
                store.regenerateDeviceId()
                // Force-mint a fresh device id immediately so any
                // concurrent track() that races the wipe sees the
                // new id rather than a transiently missing one.
                @Suppress("UNUSED_VARIABLE")
                val _force = store.deviceId
                store.sessionId = UUID.randomUUID().toString()
                eventQueue?.dropAll()
            },
        )

        liveActivities = SendoraCloudLiveActivities(
            client = client,
            configProvider = { config },
        )

        geofences = SendoraCloudGeofences(
            client = client,
            configProvider = { config },
            userIdProvider = { currentUserId },
            anonIdProvider = { storage?.deviceId },
        )

        push = SendoraCloudPush(
            client = client,
            scope = scope,
            userIdProvider = { currentUserId },
        )

        links = SendoraCloudLinks(
            client = client,
            packageName = appContext.packageName,
            linkHosts = finalConfig.linkHosts,
            scope = scope,
        )

        isConfigured = true
        consent.subscribe { granted ->
            if (granted) scope.launch { eventQueue?.flush() }
        }

        SendoraCloudLogger.debug("Configured — project: $projectId")

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
                        if (finalConfig.autoTrackLifecycle) {
                            trackEvent("app.backgrounded", mapOf(
                                "sessionId" to (storage?.sessionId ?: "")
                            ))
                        }
                    }
                }
                override fun onStart(owner: LifecycleOwner) {
                    if (finalConfig.autoTrackLifecycle) {
                        trackEvent("app.foregrounded", mapOf(
                            "sessionId" to (storage?.sessionId ?: "")
                        ))
                    }
                }
            })
        }

        if (finalConfig.autoTrackLifecycle) {
            // app.opened fires once per `init()` (per-launch). Mirrors
            // Firebase's `app_open` auto-event.
            trackEvent("app.opened", mapOf(
                "sessionId" to (storage?.sessionId ?: "")
            ))
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

    fun handleDeepLink(intent: Intent): SendoraCloudLinkData? {
        if (!isConfigured) return null
        val uri = intent.data ?: return null
        return parseDeepLink(uri)
    }

    fun handleDeepLink(uri: Uri): SendoraCloudLinkData? {
        if (!isConfigured) return null
        return parseDeepLink(uri)
    }

    fun checkDeferredDeepLink(callback: (SendoraCloudLinkData?) -> Unit) {
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
            @Suppress("UNCHECKED_CAST")
            val linkDataMap = (data?.get("deepLinkData") as? Map<String, Any>) ?: emptyMap()
            withContext(Dispatchers.Main) {
                if (found) {
                    callback(SendoraCloudLinkData(
                        shortcode = "",
                        deepLinkPath = data?.get("deepLinkPath") as? String,
                        campaign = data?.get("campaign") as? String,
                        source = data?.get("source") as? String,
                        medium = data?.get("medium") as? String,
                        linkData = linkDataMap,
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
            SendoraCloudValidator.validateEventName(name)
            SendoraCloudValidator.validateProperties(properties)
        } catch (e: SendoraError) {
            SendoraCloudLogger.error(e.message ?: "invalid event")
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
                "sdk" to mapOf("name" to "sendora-android", "version" to "4.0.0"),
            ))
            put("sessionId", storage?.sessionId ?: "")
            put("consent", listOf("analytics"))
            currentUserId?.let { put("userId", it) }
            currentIdentityToken?.let { put("identityToken", it) }
        }
        scope.launch { eventQueue?.add(event) }
    }

    fun identify(userId: String, traits: Map<String, Any>? = null, options: SendoraCloudIdentifyOptions? = null) {
        if (!isConfigured) return
        if (userId.isEmpty() || userId.length > 256) {
            SendoraCloudLogger.error("userId must be 1-256 chars")
            return
        }
        if (traits != null) {
            // Cap traits payload at 32 KB serialized — same bound
            // sdk-web + sdk-react-native enforce. Prevents an
            // in-app actor from DoSing ingest with deeply nested
            // / large objects.
            val bytes = JSONObject(traits).toString().toByteArray(Charsets.UTF_8).size
            if (bytes > 32 * 1024) {
                SendoraCloudLogger.error("traits exceed 32 KB")
                return
            }
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

    private fun parseDeepLink(uri: Uri): SendoraCloudLinkData? {
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
        return SendoraCloudLinkData(shortcode = shortcode)
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
