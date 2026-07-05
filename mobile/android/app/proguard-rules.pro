# Keep gomobile's generated Java bindings stable for JNI. R8 can still shrink
# and obfuscate the app shell around them.
-keep class io.blinklabs.bursa.mobile.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
