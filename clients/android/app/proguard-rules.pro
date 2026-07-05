# JNA uses reflection + JNI to bind the native libraries; keep its classes and
# the UniFFI-generated binding intact so R8/ProGuard never strips the symbols
# the Rust `.so` is called through.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }

# The generated UniFFI binding + our SecretStore/EventListener callback impls are
# invoked from native code by name; don't rename or drop them.
-keep class uniffi.mycellium_sdk.** { *; }
-keep class eu.mycellium.android.** { *; }
