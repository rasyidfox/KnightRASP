# Consumer rules for the KnightRASP public API.
#
# Only the public contract must keep its names (host apps call it and remote rules
# reference check IDs). Internal implementations (check-*, probes, core) stay out of
# these rules on purpose so the consumer's R8 can rename them in release builds.
#
# Note: `check.*` / `probe.*` intentionally use a single `*` — a double `**` would
# also match subpackages (e.g. io.knightrasp.check.debug.*), which would keep every
# check implementation un-obfuscated.

-keep public class io.knightrasp.Rasp { public *; }
-keep public interface io.knightrasp.RaspListener { *; }
-keep public interface io.knightrasp.RaspRuntime { *; }
-keep public class io.knightrasp.config.** { public *; }
-keep public class io.knightrasp.model.** { public *; }
-keep public class io.knightrasp.check.* { public *; }
-keep public class io.knightrasp.probe.* { public *; }
-keep public class io.knightrasp.telemetry.** { public *; }
-keep public class io.knightrasp.util.** { public *; }
