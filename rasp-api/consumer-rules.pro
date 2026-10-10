# Consumer rules for the KnightRASP public API.
# Public names must stay stable so consumer apps can keep calling them
# after R8. Internal classes (default runtime, checks, probes) do not need
# to be kept because they are referenced directly, not via reflection.

-keep public class io.knightrasp.Rasp { public *; }
-keep public interface io.knightrasp.RaspListener { *; }
-keep public interface io.knightrasp.RaspRuntime { *; }
-keep public class io.knightrasp.config.** { public *; }
-keep public class io.knightrasp.model.** { public *; }
-keep public class io.knightrasp.check.** { public *; }
-keep public class io.knightrasp.probe.** { public *; }
-keep public class io.knightrasp.telemetry.** { public *; }
