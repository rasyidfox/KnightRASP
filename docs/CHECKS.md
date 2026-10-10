# Check Catalog

Full list of the **25 checks** in KnightRASP. Every check produces *evidence* with a
`confidence` in 0..1; the final score is computed by the engine (noisy-OR per category
+ a small cross-category bonus) — see
[README](../README.md#policy-responses-and-silent-mode).

- **Cost** determines the execution wave and timeout: `LOW` (1 s), `MEDIUM` (2 s),
  `HIGH` (3 s).
- Checks that need configuration report **Unknown** (adds no score) while their
  configuration is empty.
- Checks marked **native** report Unknown when `libguardcore.so` cannot be loaded
  (no-NDK build / unsupported ABI) — the SDK stays fail-open.

## ROOT

| ID | Cost | Confidence | Needs | Description |
|---|---|---|---|---|
| `root.su_binary` | LOW | 0.60 | – | `su` binary in common paths (`/system/bin/su`, `/system/xbin/su`, `/data/adb/...`, etc). Catches modern Magisk symlinks (`su -> magisk`). |
| `root.magisk_artifacts` | LOW | 0.70 (path) / 0.50 (package) | – | Magisk/KernelSU directories (`/data/adb/magisk`, `/sbin/.magisk`, etc) and root manager packages (Magisk, KernelSU, LSPosed, SuperSU). |
| `root.test_keys` | LOW | 0.40 | – | `Build.TAGS` contains `test-keys` (image not signed with release keys). |
| `root.native_mounts` | LOW | 0.50 | native | Root-framework artifacts in the process mount namespace (`magisk`, `kernelsu`, `ksud`), read with a raw syscall. Complements `root.su_binary` when Magisk's deny-list hides binaries and `/data/adb`. |
| `root.bootloader_state` | LOW | 0.50 | native | Verified-boot state (`ro.boot.verifiedbootstate` orange/yellow, `ro.boot.flash.locked=0`, vbmeta unlocked). Comes from the bootloader and cannot be hidden by Magisk. |

## DEBUG

| ID | Cost | Confidence | Needs | Description |
|---|---|---|---|---|
| `debug.debugger_connected` | LOW | 0.90 | – | `Debug.isDebuggerConnected()` — JDWP attached. |
| `debug.tracer_pid` | LOW | 0.90 | – | `TracerPid` in `/proc/self/status` > 0 (process is being ptraced). |
| `debug.native_ptrace` | LOW | 0.90 | native | `TracerPid` + `ptrace(PTRACE_TRACEME)` from the native layer via raw syscall. |

## HOOK

| ID | Cost | Confidence | Needs | Description |
|---|---|---|---|---|
| `hook.frida_threads` | LOW | 0.80 | – | Typical Frida thread names: `gmain`, `gdbus`, `gum-js-loop`, `pool-frida`. |
| `hook.maps_artifacts` | MEDIUM | 0.85 | – | Frida/Xposed/Substrate/LSPosed artifacts in the process memory map (`/proc/self/maps`). |
| `hook.native_maps` | LOW | 0.85 | native | Memory-map scan from C++ via raw syscall (harder to hook). |
| `hook.injected_memory` | LOW | 0.60 | native | Memory-map shapes typical of injected agents: non-ART `memfd:` mappings and writable+executable `.so` mappings — survives renaming of `frida-server`/gadget. |

## INTEGRITY

| ID | Cost | Confidence | Needs | Description |
|---|---|---|---|---|
| `integrity.signature` | LOW | 0.95 | `expectedSignatureSha256` | Compares the APK signer certificate SHA-256 against the pin. Detects repackaging. |
| `integrity.installer` | LOW | 0.50 (sideload) / 0.60 (other installer) | `allowedInstallers` | Installation source outside the allow-list (e.g. `com.android.vending`). |
| `integrity.native_text` | LOW | 0.90 | native | Compares the executable segment against a **build-time pinned digest** (filled after stripping; detects pre-load patching such as gadget/spawn or a repackaged `.so`) and against a load-time baseline (post-load inline hooks / memory patches). |
| `integrity.sdk_library_origin` | MEDIUM | 0.85 | native | Verifies the SDK native library is loaded from the app install directory, not `/data/local/tmp` or elsewhere. |

## EMULATOR

| ID | Cost | Confidence | Needs | Description |
|---|---|---|---|---|
| `emulator.props` | LOW | 0.20–0.60 per signal | – | Emulator-typical fingerprint/model/hardware/product/ABI (goldfish, ranchu, sdk_gphone, vbox, etc). |
| `emulator.files` | LOW | 0.50 | – | QEMU/Genymotion device files (`/dev/qemu_pipe`, `/dev/socket/genyd`, etc). |
| `emulator.cpuinfo` | LOW | 0.60 | – | Emulator markers in `/proc/cpuinfo` (`goldfish`, `ranchu`, `qemu`). Independent of `Build.*`, so spoofed vendor fingerprints do not hide it. |

## ENVIRONMENT

| ID | Cost | Confidence | Needs | Description |
|---|---|---|---|---|
| `env.developer_options` | LOW | 0.30 | – | Developer options enabled. Weak signal; auto-disabled in `Environment.QA`. |
| `env.adb_enabled` | LOW | 0.40 | – | ADB enabled. Medium signal; auto-disabled in `Environment.QA`. |
| `env.mock_location` | LOW | 0.50 | – | Mock location enabled (`Settings.Secure`). |
| `env.accessibility_services` | LOW | 0.40 | `allowedAccessibilityServices` | Accessibility services outside the allow-list (e.g. unknown auto-clickers/screen readers). |

## VIRTUALIZATION

| ID | Cost | Confidence | Needs | Description |
|---|---|---|---|---|
| `virtualization.cloner_app` | LOW | 0.35 | – | App-cloner/parallel-space hosts installed (Parallel Space, DualSpace, etc). Weak signal. |
| `virtualization.process_name` | LOW | 0.30 | – | Process name (`/proc/self/cmdline`) contains virtual/parallel environment markers. Weak signal. |

---

## Tuning

**Disable specific checks:**

```kotlin
RaspConfig(disabledChecks = setOf("env.adb_enabled", "env.developer_options"))
```

**Lower confidence without shipping an app update** (remote rules, see README):

```json
{
  "version": 1,
  "confidenceScale": {
    "integrity.installer": 0.5,
    "virtualization.cloner_app": 0
  },
  "disabledChecks": ["env.mock_location"],
  "thresholds": { "low": 0.3, "medium": 0.6, "high": 0.85 }
}
```

**On-device diagnostics:** enable `RaspConfig(debugLogging = true)` (debug builds only;
release builds contain no logging code at all) to see `assessment ... categories=[...]`
lines and the evidence list in logcat.
