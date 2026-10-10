# Consumer rules for the `rasp` aggregate module.

# The framework instantiates the ContentProvider via its class name from the manifest.
-keep class io.knightrasp.internal.KnightRASPInitProvider { *; }

# JNI: native class & method names are a contract with libknightrasp.so.
-keep class io.knightrasp.nativebridge.JniBridge { *; }
