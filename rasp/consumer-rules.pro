# Consumer rules modul agregat `rasp`.

# ContentProvider diinstansiasi framework lewat nama kelas dari manifest.
-keep class io.knightrasp.internal.KnightRASPInitProvider { *; }

# JNI: nama kelas & method native adalah kontrak dengan libknightrasp.so.
-keep class io.knightrasp.nativebridge.NativeProbeImpl { *; }
