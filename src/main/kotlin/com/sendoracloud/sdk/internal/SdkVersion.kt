package com.sendoracloud.sdk.internal

/**
 * Single source of truth for the SDK version string (ADR-023 §7).
 *
 * Emitted in the event body `context.sdk.version` AND sent on every request
 * as the `X-Sendora-SDK-Version` header. Keep this in lockstep with the
 * `version` declared in `build.gradle.kts` on every release. A single Kotlin
 * const is deliberately the source of truth — `buildConfig` is disabled in
 * this module (`buildFeatures { buildConfig = false }`), so wiring a
 * BuildConfig field would add machinery for no benefit.
 */
internal const val SDK_VERSION = "4.6.0"

/** SDK name reported in telemetry + the `X-Sendora-SDK-Name` header. */
internal const val SDK_NAME = "sendora-android"
