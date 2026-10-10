# KnightRASP Architecture — Android RASP as an SDK

| | |
|---|---|
| Status | Living document — Phases 1–4 implemented and verified |
| Language | Kotlin (Java-friendly public API), C/C++ for native |
| Distribution | AAR via Maven (local publishing available, Central pending) |
| Package group | `io.knightrasp` (public API), internal classes R8-friendly |

This document describes the architecture of KnightRASP (Runtime Application
Self-Protection) for Android, distributed as an SDK. It covers module layout, API
contracts, the check execution engine, scoring/policy, the native layer, and the
testing/release strategy.

---

## Table of contents

1. [Goals & scope](#1-goals--scope)
2. [Design principles](#2-design-principles)
3. [Threat model](#3-threat-model)
4. [Architecture overview](#4-architecture-overview)
5. [Gradle modules & responsibilities](#5-gradle-modules--responsibilities)
6. [Public API design](#6-public-api-design)
7. [Detection data model](#7-detection-data-model)
8. [Engine: scheduler, stages, lifecycle](#8-engine-scheduler-stages-lifecycle)
9. [Scoring & policy](#9-scoring--policy)
10. [Response actions](#10-response-actions)
11. [Probe layer](#11-probe-layer)
12. [Native layer](#12-native-layer)
13. [Telemetry](#13-telemetry)
14. [Remote rule updates](#14-remote-rule-updates)
15. [Check catalog per category](#15-check-catalog-per-category)
16. [Multi-process & app lifecycle](#16-multi-process--app-lifecycle)
17. [Securing the SDK itself](#17-securing-the-sdk-itself)
18. [Distribution, versioning, compatibility](#18-distribution-versioning-compatibility)
19. [Testing & QA](#19-testing--qa)
20. [CI/CD](#20-cicd)
21. [Performance budget](#21-performance-budget)
22. [Privacy & compliance](#22-privacy--compliance)
23. [Roadmap](#23-roadmap)
24. [Common pitfalls](#24-common-pitfalls)
25. [Open design decisions](#25-open-design-decisions)

---

## 1. Goals & scope

**Goal.** Provide an embeddable Android SDK that detects runtime threats (root,
hooking, debuggers, emulators, tampering, hostile environments) and gives the app the
ability to respond (log, degrade features, log out, terminate).

**In scope:**

- Layered signal-based detection with confidence scores, not booleans.
- Stable, Java-friendly, dependency-minimal public API.
- Plugin-based check registry, staged by cost.
- Host-configurable policy & responses.
- A native layer for checks that cannot be trusted in Java.
- Telemetry as an interface (no-op by default).

**Out of scope (at least for early versions):**

- The backend itself (only the `TelemetrySink` contract / ingest endpoint is defined).
- Anti-piracy / DRM.
- Defense against attackers with full kernel control (beyond any app's ability; RASP
  raises the cost of attack, it does not offer guarantees).

---

## 2. Design principles

1. **Every detection is a plugin.** One check = one unit with one responsibility,
   registered in a registry, toggleable per build or per config.
2. **Detection ≠ Scoring ≠ Policy ≠ Response.** Detection yields raw evidence; scoring
   aggregates; policy belongs to the host app; responses execute.
3. **Signals, not booleans.** A single trait proves nothing. Use many signals with
   their own `confidence`; aggregate probabilistically.
4. **Minimal & Java-friendly public API.** No `suspend` in the public API. Avoid
   forcing transitive dependencies (WorkManager, Room, OkHttp, etc.).
5. **Fail-open by default.** Internal SDK errors must never take the host app down.
6. **The SDK is a client, not the final judge.** Critical decisions (session
   revocation, account blocking) are re-validated on the backend with Play Integrity
   and server-side signals.
7. **Testable without a device.** All OS access goes through probe interfaces so
   checks can be unit-tested on the JVM.
8. **The SDK itself is a target.** Assume the RASP code is read by attackers; strength
   comes from obfuscation + server verification, not algorithm secrecy.

---

## 3. Threat model

Priorities based on realistic field threats:

| Priority | Adversary | Example attack | Defense focus |
|---|---|---|---|
| P0 | Automated repackaging / trojan | Modified APK, injected ads, stolen credentials | signature & integrity verification, Play Integrity |
| P1 | Fraud farm | many instances on emulators/cloners, automation scripts | emulator, virtualization, mock location, hook detection |
| P2 | Dynamic instrumentation | Frida/Xposed to bypass logic, dump secrets | anti-hook, anti-debug, runtime integrity |
| P3 | Jailbroken users | custom ROM, Magisk, local patches | root detection with false-positive tolerance |

**Assumption.** An attacker with full kernel/firmware control can defeat almost any
detection. A good RASP raises the cost (time, skill, devices) until attacks are no
longer economical — it does not offer absolute guarantees.

---

## 4. Architecture overview

```
┌──────────────────────────────────────────────────────────┐
│ Host app: Rasp.init() · Rasp.scan() · RaspListener       │
├──────────────────────────────────────────────────────────┤
│ rasp-api (public, stable) — config, model, listener      │
├──────────────────────────────────────────────────────────┤
│ rasp-core — scheduler · registry · scorer · policy ·     │
│             response · lifecycle                         │
├──────────────────────────────────────────────────────────┤
│ check-* — root · hook · debug · emulator · integrity ·   │
│           environment · virtualization                   │
├──────────────────────────────────────────────────────────┤
│ probes — file · proc · package · settings · native       │
├──────────────────────────────────────────────────────────┤
│ platform — Android SDK · JNI/libc · direct syscall       │
└──────────────────────────────────────────────────────────┘
```

Dependency rule between layers: **downward only, never upward.**

- `rasp-api` depends on nothing but the stdlib.
- `rasp-core` depends on `rasp-api`.
- `check-*` depends on `rasp-api` + probe interfaces, never on the OS directly.
- The probe layer may touch the Android SDK / JNI.
- The `sample` module and tests may depend on everything.

---

## 5. Gradle modules & responsibilities

```
KnightRASP/
├── settings.gradle.kts
├── gradle/libs.versions.toml
├── rasp-api/            # public contracts: Rasp, RaspConfig, CheckResult, Evidence, listener
├── rasp-core/           # engine: registry, scheduler, scorer, policy, response
├── rasp-checks/         # check implementations, one module per category
│   ├── check-root/      # Phase 1
│   ├── check-debug/     # Phase 1 (+ native Phase 2)
│   ├── check-emulator/  # Phase 1
│   ├── check-environment/ # Phase 1
│   ├── check-hook/      # Phase 2
│   ├── check-integrity/ # Phase 2 (+ SDK anti-tamper in Phase 4)
│   ├── check-virtualization/ # Phase 4
│   └── check-network/   # not implemented
├── rasp-probes/         # concrete probe implementations (Android + native)
├── rasp-testing/        # fake probes + testContext() for check unit tests
├── rasp-native/         # C/C++ + JNI: anti-debug, anti-hook, integrity, kill (Phase 2)
├── rasp-telemetry/      # persistent queue + batching + retry (Phase 3)
├── rasp-rules/          # signed data-only rules (Phase 3)
├── rasp-playintegrity/  # Play Integrity token client (Phase 3)
├── rasp/                # aggregate AAR + runtime auto-attach (what consumers use)
└── sample/              # sample app + instrumented test
```

Implementation note: check directories live directly at the project root
(`check-root/`, not `rasp-checks/check-root/`) — still one Gradle module per category
as planned, just without the wrapper folder.

**Publishing model:** consumers use **one aggregate artifact** (`io.knightrasp:rasp`)
assembled from the internal modules. Modules are split for maintainability, not to
make consumers pick and choose. A `rasp-lite` variant (no native) is planned for apps
that do not want to ship `.so` files.

Splitting checks per category (instead of one big module) helps during false-positive
tuning and when part of a team only touches one category.

---

## 6. Public API design

Principles: small, stable, Java-friendly, no reflection on the consumer side.

```kotlin
interface RaspListener {
    fun onAssessment(result: ThreatAssessment) {}
    fun onError(error: RaspError) {}
}

data class RaspConfig @JvmOverloads constructor(
    val mode: Mode = Mode.MONITOR,                      // MONITOR | PROTECT
    val environment: Environment = Environment.RELEASE, // RELEASE | QA
    val enabledChecks: Set<String> = emptySet(),        // empty = all
    val disabledChecks: Set<String> = emptySet(),
    val thresholds: Thresholds = Thresholds(low = 0.3f, medium = 0.6f, high = 0.85f),
    val policy: Policy = Policy.ALERT_ONLY,
    val telemetry: TelemetrySink = TelemetrySink.NOOP,
    val multiProcess: MultiProcessMode = MultiProcessMode.MAIN_ONLY,
    val expectedSignatureSha256: Set<String> = emptySet(), // -> integrity.signature
    val allowedInstallers: Set<String> = emptySet(),       // -> integrity.installer
    val hostActions: HostActions = HostActions.NONE,       // -> Degrade/Logout/BlockSensitiveOps
    val rules: RaspRules? = null,                          // verified remote tuning
    val allowedAccessibilityServices: Set<String> = emptySet(),
    val debugLogging: Boolean = false,                     // no logging code at all in release
)

object Rasp {
    /** Must complete in < 10 ms. No I/O. */
    fun init(app: Application, config: RaspConfig)

    /** Async scan; results are delivered to listeners. */
    fun scan(trigger: Trigger = Trigger.ON_DEMAND)

    /** Blocking gate for critical flows (login, transfers), hard timeout. */
    fun scanSync(timeoutMs: Long): ThreatAssessment

    fun addListener(listener: RaspListener)
    fun removeListener(listener: RaspListener)
    fun attachRuntime(runtime: RaspRuntime) // used by the aggregate module's initializer
}
```

API notes:

- `object Rasp` is a plain singleton; all methods are safe to call repeatedly.
- `scan()` never throws to the caller; errors go to `onError`.
- `scanSync()` has a hard timeout; on timeout it returns `Unknown` (no crash).
- `Trigger` enum: `ON_INIT`, `ON_FOREGROUND`, `ON_DEMAND`, `PERIODIC`.
- `Environment.QA` automatically disables development-noise checks (debugger, ADB,
  developer options) so development is not blocked.

Automatic initialization is provided through a ContentProvider in the `rasp` module
(Firebase-style), attaching the default runtime **before** `Application.onCreate`, so
consumers only call `Rasp.init(...)`.

---

## 7. Detection data model

```kotlin
interface RaspCheck {
    val id: String             // "root.su_binary" — stable, used for config & tuning
    val category: Category     // ROOT, HOOK, DEBUG, EMULATOR, INTEGRITY, ENVIRONMENT, VIRTUALIZATION
    val cost: Cost             // LOW, MEDIUM, HIGH -> execution wave & timeout
    fun run(ctx: RaspContext): CheckResult
}

sealed interface CheckResult {
    data object Clean : CheckResult
    data class Detected(val evidence: List<Evidence>) : CheckResult
    data class Unknown(val reason: String) : CheckResult
}

data class Evidence(
    val ruleId: String,
    val confidence: Float,     // 0..1 — confidence that this signal is real
    val detail: String? = null,
)

data class ThreatAssessment(
    val score: Float,          // 0..1 (global)
    val level: Level,          // NONE, LOW, MEDIUM, HIGH, CRITICAL
    val categories: Map<Category, Float>,
    val evidence: List<Evidence>,
    val timestampMs: Long,
)
```

`confidence` guidelines:

- 0.9–1.0: a signal that practically never appears on a normal device (e.g. an active
  Frida agent).
- 0.6–0.8: strong indication, but possible in legitimate environments (e.g. an `su`
  binary on a custom ROM).
- 0.3–0.5: weak indication (e.g. developer options enabled).
- Values should be tuned from field data and kept as constants per check so they are
  easy to audit and adjust via rule updates.

The `RaspContext` handed to checks contains: the app's package name, a config
snapshot, the probe set, and `nowMs`. Checks **must not** access the OS directly —
everything goes through probes.

---

## 8. Engine: scheduler, stages, lifecycle

The scan engine is staged by cost instead of running everything at once:

| Stage | When | Contents | Budget |
|---|---|---|---|
| 0 `INIT` | `init()` synchronous on main thread | config validation only (no I/O) | < 10 ms |
| 1 `FAST` | background at startup | `Cost.LOW` checks (files, properties, settings, native quick checks) | ~200 ms |
| 2 `DEEP` | background / on-demand | `Cost.MEDIUM/HIGH` checks (maps scans, heavier work) | 1–2 s |
| 3 `REMOTE` | async | Play Integrity, rule fetching | seconds |

Engine rules:

- **Per-check isolation.** Each check runs in its own worker coroutine with a
  cost-based timeout; timeouts are *abandoned* (results dropped) without holding the
  scan — stragglers finish on their own I/O threads.
- **Cache.** Results are cached per check with a TTL by cost: LOW 30 s, MEDIUM 5 min,
  HIGH 30 min. Repeated triggers do not repeat expensive work.
- **Coalescing.** Multiple `scan()` calls in a short window collapse into one scan.
- **No main-thread I/O.** `init()` never touches disk; listeners and responses are
  delivered on the main thread.
- **No reflection.** The check registry is wired literally (no ServiceLoader) so R8
  full mode cannot strip it.

One scan, end to end:

```
Trigger ──► Scheduler ──► for each check in the wave:
                             │  (parallel, bounded workers)
                             ▼
                        Check.run(ctx) ──► CheckResult
                             │
                             ▼
                         Scorer.aggregate ──► ThreatAssessment
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
          Policy / Response        TelemetrySink
                │
                ▼
        RaspListener.onAssessment
```

---

## 9. Scoring & policy

### 9.1 Aggregation

Per category, use *noisy-OR*:

```
categoryScore = 1 - Π (1 - confidence_i)
```

Across categories, use a conservative combination — the strongest category plus a
small bonus when ≥ 2 categories are suspicious — capped at 1.0. Rationale: many weak
signals in one category must not automatically become CRITICAL, while two independent
suspicious categories are indeed more convincing than one.

```
globalScore = min(1.0, max(categoryScore) + combinationBonus)   // bonus = 0.05
```

### 9.2 Levels

`Thresholds(low, medium, high)` maps the score to a `Level`:
`≥ high` → CRITICAL, `≥ medium` → HIGH, `≥ low` → MEDIUM, `> 0` → LOW. All threshold
values are host configuration and can be overridden by remote rules.

### 9.3 Policy

Policy is a pure function owned by the host:

```kotlin
val policy = Policy { a ->
    when {
        a.level >= Level.CRITICAL -> listOf(Response.Exit, Response.Report)
        a.level >= Level.HIGH     -> listOf(Response.Logout, Response.Report)
        a.level >= Level.MEDIUM   -> listOf(Response.Degrade, Response.Report)
        else                      -> listOf(Response.Log)
    }
}
```

`Mode.MONITOR` runs the policy but skips disruptive responses (only log/report run).
`Mode.PROTECT` executes fully. This makes rollout safe: run MONITOR in production
first to measure false positives, then move to PROTECT.

---

## 10. Response actions

| Response | Effect | Notes |
|---|---|---|
| `Log` | internal log / listener | default |
| `Report` | send the assessment to `TelemetrySink` | never blocks |
| `Degrade` | disable sensitive features (biometrics, large transfers) | executed via `HostActions.degrade` |
| `Logout` | clear tokens/session, force re-login | executed via `HostActions.logout` |
| `BlockSensitiveOps` | reject specific operations until review | executed via `HostActions.blockSensitiveOps` |
| `Exit` | terminate the process via a native `exit_group` syscall | silent: no stack trace, no dialog, no ANR |
| `Custom { ... }` | arbitrary host action | runs on the main thread |

All responses can be overridden by the host. The SDK never calls `System.exit`
silently unless the host explicitly chooses `Response.Exit`. Presets such as
`Policies.silentKillOn(Level.HIGH)` exist for the common silent-kill setup.

---

## 11. Probe layer

The key to testability and the single point where all OS access is concentrated:

```kotlin
interface Probes {
    val file: FileProbe          // exists(path), read(path)
    val proc: ProcProbe          // selfStatus(), selfMaps(), selfCmdline(), threadNames()
    val packages: PackageProbe   // isInstalled, signingCertSha256, installerPackageName, apkPath
    val settings: SettingsProbe  // globalInt(key, default), secureInt(key, default)
    val system: SystemProbe      // Build properties, isDebuggerConnected, accessibility services
    val native: NativeProbe?     // moduleName, signalA..signalF, shutdown
}
```

- Production implementations read from the OS, partly via raw syscalls/native.
- Test implementations use fixtures per scenario — clean device, Magisk, active
  Frida, Xposed, emulator, custom ROM, repacked app.
- The native probe **does not expose** raw primitives to checks; checks only see
  booleans/data, so anti-hook details do not leak to the Java layer.
- `NativeProbe` is nullable: when the native library cannot be loaded (e.g. a
  no-NDK build), dependent checks report `Unknown` and the SDK stays fail-open.

---

## 12. Native layer

The native library is used for things that cannot be trusted in Java/Kotlin:

1. **Anti-debug:** `ptrace(PTRACE_TRACEME)` (called once, cached) and `TracerPid`
   parsing from `/proc/self/status`, both via direct syscalls on arm64.
2. **Anti-hook:** `/proc/self/maps` scan for Frida/Xposed/Substrate/LSPosed markers.
4. **Integrity:** FNV-1a hash of the library's own executable segment (baseline on
   first call, compared afterwards).
5. **Response:** process termination via the `exit_group` syscall.

Implementation guidelines:

- Use **direct syscalls (inline SVC assembly)** for critical operations so they
  cannot be intercepted through the PLT (32-bit ARM and x86_64 fall back to libc
  `syscall()`; 32-bit Thumb reserves `r7`, so the assembly path is not possible).
- Do not rely on libc where it is trivially hooked; keep a fallback when direct
  syscalls are blocked by some OEMs.
- Obfuscate native code with OLLVM (control-flow flattening, string encryption) —
  still on the roadmap.
- ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64` (emulator/testing).
- The output library name is configurable (`knightrasp.nativeLibName`, default
  `guardcore`) so it is not easily fingerprinted from the file name; one value is
  used consistently by Gradle → CMake → Kotlin.
- Keep the JNI bridge as thin as possible; validate inputs on both sides.

---

## 13. Telemetry

```kotlin
fun interface TelemetrySink {
    fun report(assessment: ThreatAssessment)
    companion object { val NOOP: TelemetrySink = TelemetrySink { } }
}
```

- **Default no-op.** The SDK never silently sends data anywhere.
- The optional `rasp-telemetry` module provides: a persistent JSON-Lines queue
  (bounded; oldest events are dropped when full), batching, retry with exponential
  backoff, a minimum level filter, and a redaction hook.
- Minimal payload: check ids, level, score, categories, SDK version — no device
  identifiers unless the host adds them.
- `report()` only touches the queue (no network) and is safe to call from the main
  thread; uploads happen on a dedicated scheduler.

---

## 14. Remote rule updates

- Rules carry: per-check confidence scaling, threshold overrides, enable/disable
  lists — the tuning knobs that would otherwise require an app update.
- **Data-only format** (JSON), **signed** (ECDSA P-256) and verified client-side
  against an embedded public key.
- No free-form scripts/expressions — this prevents rule updates from becoming an RCE
  vector.
- Verified rules are applied at init; expired or invalid rules are ignored entirely
  (fail-open to the static config).
- Fallback: if download/verification fails, built-in defaults apply; a rules failure
  must never block the app.

---

## 15. Check catalog per category

The full, exact list of the 21 implemented checks (ids, cost, confidence, required
configuration) lives in [CHECKS.md](CHECKS.md). Candidate categories and their
false-positive characteristics:

| Category | Example signals | Cost | FP notes |
|---|---|---|---|
| Root | `su` paths, Magisk/KernelSU artifacts, `test-keys`, mount flags | low–medium | high on custom ROMs; requires multiple signals |
| Hook | Xposed/Frida maps, thread names, ports, pipes | medium | moderate; use `Environment.QA` for the team's own QA |
| Debugger | `Debug.isDebuggerConnected`, JDWP, `TracerPid`, `ptrace` | low | low |
| Emulator | fingerprint/hardware `goldfish`/`ranchu`, qemu files, ABI | low | moderate (WSA/ChromeOS) |
| Integrity | signature digest vs pin, installer, native text, library origin | low–medium | low |
| Environment | ADB/dev options, mock location, accessibility, tapjacking | low | moderate (TalkBack etc.) |
| Virtualization | cloner packages, suspicious process names | low | moderate |
| Network | certificate pinning helper, proxy/MITM detection | medium | low (not implemented) |

---

## 16. Multi-process & app lifecycle

- Default `MultiProcessMode.MAIN_ONLY`: the full scan runs only in the main process;
  `:remote`/service processes skip the engine (saves resources, avoids duplicate
  events).
- `MultiProcessMode.ALL` exists for apps that need per-process protection, with the
  constraint of no duplicate telemetry and per-process caches.
- Lifecycle triggers without forcing a lifecycle dependency:
  `Application.ActivityLifecycleCallbacks` drives `ON_FOREGROUND`.
- `PERIODIC` is optional; the SDK does **not** force WorkManager. Hosts that want
  background periodicity schedule it themselves and call `Rasp.scan()`.

---

## 17. Securing the SDK itself

1. **No logging in release.** The release variant of the internal logger is a no-op and
   all call sites are gated by a compile-time `false`, so R8 removes the logging code
   and its strings entirely (verified against the release dex).
2. **String obfuscation (Java/Kotlin).** Detection-sensitive constants (root paths,
   hook markers, `/proc` paths, settings keys, package lists) are stored as XOR+hex
   blobs and decoded at runtime; the native library name is obfuscated the same way.
3. **Native string encryption.** C++ paths/markers and the JNI class name are
   compile-time XOR-encrypted (`Enc`) and never appear in `.rodata`.
4. **JNI surface reduction.** Methods are bound through `RegisterNatives` in
   `JNI_OnLoad`; no `Java_*` symbols are exported, and the library locates itself via
   `dladdr()` instead of a file-name string.
5. **Binary hardening.** Full RELRO + immediate binding, non-executable stack,
   hidden visibility, `--exclude-libs,ALL`, debug symbols stripped in release, raw
   syscalls for integrity-critical reads on arm64.
6. **SDK anti-tamper checks.** `integrity.native_text` (executable-segment baseline)
   and `integrity.sdk_library_origin` (the native library must load from the app's
   install directory, not `/data/local/tmp`).
7. **Consumer ProGuard rules** ship inside the AAR so consumers need no extra
   configuration and only the public API (plus the JNI boundary) is kept.
8. **No secrets.** No API keys or secret algorithms inside the SDK; assume attackers
   read everything.
9. **Open-source readiness.** Because the detections are transparent, strength must
   come from tuning, obfuscation, and server-side verification.
10. **Not implemented (future):** a packer/encrypted-dex loader and OLLVM
    control-flow flattening. These raise the bar further but are not a substitute for
    server-side decisions.

---

## 18. Distribution, versioning, compatibility

- **minSdk:** 23 (Android 6.0). Target SDK: latest.
- **ABIs:** `arm64-v8a`, `armeabi-v7a`, `x86_64`.
- **Size:** target < 1–2 MB per ABI; small method count; no heavy resources.
- **Artifacts:** `io.knightrasp:rasp` today; a `rasp-lite` (no native) variant is planned.
- **Semantic versioning** + binary-compatibility validation in CI; public API changes
  only in major versions with a one-minor deprecation policy.
- **Manifest merger:** the SDK adds `<queries>` for package visibility (Android 11+)
  and **never** requests `QUERY_ALL_PACKAGES`.
- **KDoc** for the entire public API.

---

## 19. Testing & QA

1. **Unit tests (JVM).** Every check is tested with fake probes (`rasp-testing`) for
   scenarios: clean device, Magisk, active Frida, Xposed, emulator, custom ROM,
   repacked app. Current suite: 114 tests.
2. **Instrumented tests.** Emulator matrix API 23–36 + device farm (still to be set up).
3. **Dedicated devices.** A standing pipeline for **rooted + Magisk** devices and
   **active Frida-server** to prove detections actually fire, not merely "don't error".
4. **False-positive sweep.** Run on a catalog of popular devices (Xiaomi/custom ROMs
   are the root FP hotspot) and record per-check results.
5. **Benchmarks.** Macrobenchmark for startup impact; target: added
   `Application.onCreate` time < 20 ms p95 in release.
6. **Stability.** Fail-open tests: a probe that throws must produce `Unknown`, not a crash.

---

## 20. CI/CD

- Jobs: lint (ktlint/detekt) → unit tests → obfuscated release build → instrumented
  test subset → publish snapshot.
- Two build variants: `debug` (verbose, all non-release checks) and `release`
  (no logging code, minified consumer builds).
- Sign release artifacts; publish checksums for `lib*.so` and AARs.
- Keep R8 mapping files private for crash de-obfuscation.
- Local publishing is available now (`./gradlew publishToMavenLocal`, group
  `io.knightrasp`, version from the root `build.gradle.kts`); Maven Central comes
  after the API stabilizes.

---

## 21. Performance budget

| Metric | Target |
|---|---|
| `init()` | < 10 ms, no I/O |
| FAST wave | ~200 ms total (background) |
| DEEP wave | 1–2 s total (background), per-check timeout 1–3 s by cost |
| Added resident memory | < 5 MB (the maps buffer is reused; the cached string is released after its TTL) |
| AAR size | < 1–2 MB per ABI |
| Idle CPU | zero (no polling); everything is trigger-based |

---

## 22. Privacy & compliance

- Minimum data; no device identifiers sent by default.
- Must be declared in Play Data Safety; this document does not replace legal review.
- Comply with GDPR and Indonesia's PDP Law (UU 27/2022): basis for processing,
  retention, and data-subject rights.
- Provide a consent option for telemetry; `TelemetrySink.NOOP` must truly send zero
  bytes.
- Do not use detection as a pretext for collecting broader user profiles than
  security requires.

---

## 23. Roadmap

**Phase 1 — Foundation (MVP). ✅**
`rasp-api` + `rasp-core` + probe layer + registry + scoring + the first 10 checks
(root, debugger, emulator, ADB/dev options) + listener + sample app.

**Phase 2 — Native & integrity. ✅**
`rasp-native` (anti-debug, anti-hook, `.text` integrity, kill via syscall), hook
checks (Frida/Xposed), integrity checks (APK signature, installer, native text), and
`Degrade`/`Logout`/`BlockSensitiveOps` responses through `HostActions`.

**Phase 3 — Operations (mostly done).**
Optional telemetry (queue + batching + retry), signed data-only remote rules
(ECDSA P-256), Play Integrity token client (server-side verdict), and local Maven
publishing (`publishToMavenLocal`). Remaining: Maven Central and the device-matrix
QA + FP sweep.

**Phase 4 — Advanced (mostly done).**
SDK anti-tamper (`integrity.sdk_library_origin` + `integrity.native_text`),
overlay/tapjacking (`TouchSafety`), screen capture (`ScreenGuard` / FLAG_SECURE),
virtualization/app cloner (`virtualization.*`), accessibility abuse
(`env.accessibility_services`). Server-side signal correlation is backend work; the
device matrix remains.

---

## 24. Common pitfalls

- **Synchronous I/O in `init()`** → ANR. All I/O must happen in background stages.
- **Reflection into hidden APIs** → greylisted/breaks on every Android update.
- **A single check as final proof** (e.g. only `su`) → heavy false positives on
  custom ROMs.
- **Forgetting multi-process** → scans run repeatedly, telemetry duplicates.
- **Forcing dependencies** (WorkManager/Room/OkHttp) → version conflicts with hosts.
- **Fail-closed defaults** → an SDK bug takes the host app down.
- **`QUERY_ALL_PACKAGES`** → rejected by Play for general use; use `<queries>`.
- **Script-based rule updates** → RCE vector. Always data-only + signatures.
- **Secrets inside the SDK** → guaranteed to be read. API keys do not belong in an AAR.
- **`System.exit` from the main thread** → easy to hook; use the native `exit_group`.

---

## 25. Open design decisions

1. **minSdk:** decided — 23.
2. **Native from day one?** Decided — native landed in Phase 2 (`rasp-native`,
   arm64/v7a/x86_64, fail-open when the `.so` is unavailable).
3. **Public API language:** decided — Kotlin with `@JvmStatic`/`@JvmOverloads`
   (Java interop is covered by a Java consumer smoke test).
4. **Bundled telemetry:** decided — interface in `rasp-api`, optional queue
   implementation in `rasp-telemetry`.
5. **License & open source:** decided — MIT (see `LICENSE`).
6. **Distribution:** local Maven works today; Maven Central / GitHub Packages pending.
7. **Play Integrity timing:** decided — Phase 3 module (`rasp-playintegrity`);
   verdict verification stays server-side.
