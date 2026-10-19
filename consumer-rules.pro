# Keep public SDK classes so R8/ProGuard don't strip them from consumer apps.
-keep public class com.sendoracloud.sdk.** { public *; }
-keepclassmembers class com.sendoracloud.sdk.** {
    public <methods>;
    public <fields>;
}

# Keep kotlinx.coroutines and androidx.lifecycle internals we depend on.
-keepnames class kotlinx.coroutines.** { *; }
-keep class androidx.lifecycle.ProcessLifecycleOwner { *; }

# Optional dependencies (4.29.0). The SDK compiles against these `compileOnly`, so an app that does
# not add them has none of their classes — R8 (AGP 8: missing classes are an ERROR) refused to
# minify such an app with "Missing class com.android.installreferrer.api.InstallReferrerClient" /
# "com.google.android.gms.location.*". The SDK probes for them with Class.forName before any use
# (PlayInstallReferrer.isAvailable / SendoraCloudGeofences.isLocationAvailable), so their absence is
# safe at runtime; these lines only tell R8 that the absence is expected.
-dontwarn com.android.installreferrer.**
-dontwarn com.google.android.gms.location.**
# When the app DOES include them, keep the probed class names stable so the Class.forName probes
# still find them after obfuscation (a no-op when the class is absent).
-keepnames class com.android.installreferrer.api.InstallReferrerClient
-keepnames class com.google.android.gms.location.LocationServices
