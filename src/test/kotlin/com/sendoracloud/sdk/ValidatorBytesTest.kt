package com.sendoracloud.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * s58.405 — `validateProperties` counts UTF-8 BYTES (its error always said "bytes"; it counted UTF-16 chars, so
 * ~10,900 three-byte characters — ~32 KB of chars, ~98 KB on the wire — passed), and the key message states the pattern's real minimum (19+, not 17+).
 */
class ValidatorBytesTest {
    private val limit = 32 * 1024
    /** `{"s":"<payload>"}` — 8 bytes around the payload. */
    private fun wrap(payload: String): Map<String, Any?> = mapOf("s" to payload)

    @Test
    fun `an ASCII payload at the byte limit passes, one byte over is refused`() {
        SendoraCloudValidator.validateProperties(wrap("a".repeat(limit - 8)))
        assertThrows(SendoraError.PayloadTooLarge::class.java) { SendoraCloudValidator.validateProperties(wrap("a".repeat(limit - 7))) }
    }

    // "中" (U+4E2D) = 3 UTF-8 bytes, 1 char. Not "€": the JVM's org.json (the test classpath) escapes U+2000–U+20FF
    // as `\u20ac`, Android's does not — "中" serialises raw on both, so the measured bytes are the device's.
    @Test
    fun `a multi-byte payload just over the byte limit is refused though its char count is a third of it`() {
        SendoraCloudValidator.validateProperties(wrap("中".repeat((limit - 8) / 3)))
        val e = assertThrows(SendoraError.PayloadTooLarge::class.java) {
            SendoraCloudValidator.validateProperties(wrap("中".repeat((limit - 8) / 3 + 1)))
        }
        assertEquals(true, e.message?.endsWith("payload too large: ${limit + 3} bytes"))
    }

    @Test
    fun `the key message matches the pattern`() {
        SendoraCloudValidator.validateApiKey("pk_" + "a".repeat(16))
        val e = assertThrows(SendoraError.InvalidApiKey::class.java) { SendoraCloudValidator.validateApiKey("pk_" + "a".repeat(15)) }
        assertEquals(true, e.message?.contains("expected pk_ followed by 16+ letters, digits, _ or - (19+ chars)"))
    }
}
