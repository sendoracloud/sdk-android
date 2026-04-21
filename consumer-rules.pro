# Keep public SDK classes so R8/ProGuard don't strip them from consumer apps.
-keep public class com.sendoracloud.sdk.** { public *; }
-keepclassmembers class com.sendoracloud.sdk.** {
    public <methods>;
    public <fields>;
}

# Keep kotlinx.coroutines and androidx.lifecycle internals we depend on.
-keepnames class kotlinx.coroutines.** { *; }
-keep class androidx.lifecycle.ProcessLifecycleOwner { *; }
