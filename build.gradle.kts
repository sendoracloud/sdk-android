plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

android {
    namespace = "com.sendoracloud.sdk"
    compileSdk = 34
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = false }
    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.lifecycle:lifecycle-process:2.8.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // Credential Manager — passkey register + authenticate (API 28+ at runtime;
    // SDK keeps minSdk = 26 by gating Build.VERSION.SDK_INT in SendoraCloudPasskeys).
    implementation("androidx.credentials:credentials:1.3.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.3.0")
    // Geofencing (s58.22) — Google Play Services Location for region monitoring.
    // Host app must also include this; declared `compileOnly` so SDK doesn't
    // force-pull a Google Play dependency on customers that don't need geofences.
    compileOnly("com.google.android.gms:play-services-location:21.3.0")
    // Play Install Referrer (Wave 51) — surfaces the URL-encoded referrer
    // string Play Store attached to the install. Used by reportInstallIfNeeded
    // to call /attribution/install-referrer for deterministic attribution
    // (utm / gclid / fbclid / ttclid / sendora_link_id) when the referrer is
    // available. `compileOnly` so the dep is opt-in — host app adds it when
    // they want install-referrer support; SDK falls back to /attribution/install
    // otherwise.
    compileOnly("com.android.installreferrer:installreferrer:2.2")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.sendoracloud"
                artifactId = "sdk-android"
                version = "4.1.0"
                pom {
                    name.set("Sendora Cloud Android SDK")
                    description.set("Deep linking, attribution, and event tracking for Android.")
                    url.set("https://sendoracloud.com/sdks")
                    licenses {
                        license {
                            name.set("Apache-2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        }
                    }
                    developers {
                        developer {
                            id.set("sendora")
                            name.set("Sendora")
                            email.set("hello@sendoracloud.com")
                        }
                    }
                    scm {
                        url.set("https://github.com/sendoracloud/sdk-android")
                    }
                }
            }
        }
    }
}
