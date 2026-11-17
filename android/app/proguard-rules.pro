# Keep all xray-rust-mobile JNI classes, callbacks, and data classes intact
-keep class org.xrayrust.mobile.** { *; }
-dontwarn org.xrayrust.mobile.**

# Keep our Rust velox-engine JNI bridge methods intact
-keep class app.velox.vpn.core.VeloxNative { *; }

# Keep Android Services & Quick Settings Tile entrypoints
-keep class app.velox.vpn.service.** { *; }

# Remove verbose debug logs in release build
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
