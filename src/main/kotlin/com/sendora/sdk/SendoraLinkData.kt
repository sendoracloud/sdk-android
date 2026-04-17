package com.sendora.sdk

/**
 * Data returned when a Sendora deep link is handled.
 */
data class SendoraLinkData(
    val shortcode: String,
    val deepLinkPath: String? = null,
    val fallbackUrl: String? = null,
    val campaign: String? = null,
    val source: String? = null,
    val medium: String? = null,
    val channel: String? = null,
    val linkData: Map<String, Any> = emptyMap(),
    val clickId: String? = null,
)
