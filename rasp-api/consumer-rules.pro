# Consumer rules untuk API publik KnightRASP.
# Nama publik harus stabil agar aplikasi konsumen tetap dapat memanggilnya
# setelah R8. Kelas internal (default runtime, checks, probes) tidak wajib
# di-keep karena direferensikan langsung, bukan lewat reflection.

-keep public class io.knightrasp.Rasp { public *; }
-keep public interface io.knightrasp.RaspListener { *; }
-keep public interface io.knightrasp.RaspRuntime { *; }
-keep public class io.knightrasp.config.** { public *; }
-keep public class io.knightrasp.model.** { public *; }
-keep public class io.knightrasp.check.** { public *; }
-keep public class io.knightrasp.probe.** { public *; }
-keep public class io.knightrasp.telemetry.** { public *; }
