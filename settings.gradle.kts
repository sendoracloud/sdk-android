// Single-module Android library. Declares the plugin + dependency repositories
// and pins the AGP / Kotlin plugin versions so `./gradlew :publishToMavenLocal`
// (jitpack.yml) resolves them. Without this file the `com.android.library`
// plugin has no version and no repository → the build never resolves AGP, which
// is why JitPack failed with `./gradlew: No such file or directory` once the
// wrapper landed (s58.266 follow-up — the wrapper AND this file were missing).
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.library") version "8.2.2"
        id("org.jetbrains.kotlin.android") version "1.9.22"
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "sdk-android"
