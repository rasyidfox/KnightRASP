# KnightRASP

RASP (**R**untime **A**pplication **S**elf-**P**rotection) for Android — an embeddable
SDK that detects runtime threats (root, hooking, debuggers, tampering, emulators,
virtualization) and reacts according to your policy, including **silent kill with no
logs and no dialogs**.

- 28 checks across 7 categories, evidence-based with confidence scores (not booleans)
- Native anti-debug / anti-hook / integrity via C++ and raw syscalls (JNI)
- Telemetry queue, signed remote rules, Play Integrity — all optional
- Latest review: 114 unit tests passing, tested on a real device (Android 13)

**Docs:** [Architecture & design](docs/ARCHITECTURE.md) · [Check catalog](docs/CHECKS.md)

---

## Try the sample APK

A ready-to-install **release build** (R8-minified, signed with a debug key for
sideloading) is included: **[dist/KnightRASP-sample.apk](dist/KnightRASP-sample.apk)**

```bash
adb install -r dist/KnightRASP-sample.apk
```

What to expect:

- On a **clean device**: a single screen showing the assessment (level, score,
  category breakdown, top evidence).
- On a **rooted device / emulator**: the app closes itself silently within ~1 second —
  that is the `silentKillOn(HIGH)` policy working as intended, with no logs and no
  crash dialog. To explore the UI on such devices, build from source with
  `Environment.QA` or disable the relevant checks (see Configuration below).

The APK is signed with a debug key and meant for evaluation only.

> **Obfuscation note.** The distributed sample is a release build, so the consumer's
> R8 renames all internal SDK classes (`io.knightrasp.check.*`, `probe.*`, `core.*`)
> — only the public contract keeps its names (plus the JNI class, which
> `RegisterNatives` resolves by name). Inspecting a **debug** build or the raw AAR
> will still show original class names; that is the standard Android model, since
> AARs ship unminified bytecode and R8 runs when the host app is packaged.

---

## Table of contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [Configuration](#configuration)
5. [Policy, responses, and silent mode](#policy-responses-and-silent-mode)
6. [Telemetry (optional)](#telemetry-optional)
7. [Signed remote rules (optional)](#signed-remote-rules-optional)
8. [Play Integrity (optional)](#play-integrity-optional)
9. [Utilities](#utilities)
10. [Advanced customization](#advanced-customization)
11. [Check catalog](#check-catalog)
12. [Module layout](#module-layout)
13. [Build & test from source](#build--test-from-source)
14. [Status & roadmap](#status--roadmap)
15. [Security & limitations](#security--limitations)
16. [Privacy](#privacy)
17. [License](#license)

---

## Requirements

| Requirement | Version |
|---|---|
| JDK | 17+ (**full JDK**, not a JRE — `javac` is required) |
| Android SDK | `platforms;android-36` + `build-tools;36.0.0` |
| NDK | `27.3.13750724` (r27d) — for the `rasp-native` module |
| CMake | 3.22.1 + Ninja |
| Host app | `minSdk 23`+ |

Apps using the `rasp-playintegrity` module must enable `android.useAndroidX=true`
in `gradle.properties` (transitive AndroidX dependency).

---

## Installation

The SDK is published as one AAR per module, group `io.knightrasp`, version `0.1.0`.

### Option A — Local Maven (most practical today)

From the SDK repo root:

```bash
# prerequisites: JDK, Android SDK, NDK & CMake installed
./gradlew publishToMavenLocal
```

Then in your app project:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        mavenLocal() // <- add this
    }
}
```

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("io.knightrasp:rasp:0.1.0")            // required (checks + native)

    // Optional:
    implementation("io.knightrasp:rasp-telemetry:0.1.0")  // telemetry queue
    implementation("io.knightrasp:rasp-rules:0.1.0")      // signed remote rules
    // implementation("io.knightrasp:rasp-playintegrity:0.1.0") // requires useAndroidX=true
}
```

All transitive dependencies (api/core/probes/native/check-*) come automatically
through the POM.

### Option B — Composite build (straight from source)

Without publishing, point your app project at this repo:

```kotlin
// app project settings.gradle.kts
includeBuild("../knight-rasp")
```

Then use the same coordinates (`io.knightrasp:rasp:0.1.0`) — Gradle substitutes them
with the source projects. Ideal when developing the SDK and the app together.

### Option C — Private Maven repository / Maven Central

The `maven-publish` pipeline is already set up in every module. Add your target
repository (e.g. GitHub Packages/Nexus) in `publishing { repositories { ... } }`,
then `./gradlew publish`. Publishing to Maven Central remains a release task.

### Native module notes

`rasp-native` builds `.so` files for **arm64-v8a, armeabi-v7a, x86_64**. Consumer
apps that want debug-symbol stripping are advised to set the same `ndkVersion`
(or have the NDK installed) in their app module.

**The native library name is configurable** (default `libguardcore.so`, no "rasp"
in it) via `gradle.properties`:

```properties
knightrasp.nativeLibName=guardcore
```

A single value is used consistently by Gradle → CMake (`.so` output name) → Kotlin
(`System.loadLibrary`), so you only change it in one place.

---

## Quick start

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()

        Rasp.init(
            this,
            RaspConfig(mode = Mode.MONITOR), // start in MONITOR to measure first
        )

        Rasp.addListener(object : RaspListener {
            override fun onAssessment(result: ThreatAssessment) {
                // send to your backend; includes level, score, categories, evidence
            }
            override fun onError(error: RaspError) {
                // the SDK is fail-open: internal errors are reported here, the app keeps running
            }
        })

        Rasp.scan(Trigger.ON_FOREGROUND)          // async, result via listener
        val assessment = Rasp.scanSync(2_000)     // sync gate for critical flows
    }
}
```

The SDK attaches its own runtime through a ContentProvider (the `rasp` module), so
`Rasp.init(...)` is all you need — no other registration step.

---

## Configuration

`RaspConfig` (every parameter has a default; from Java use the `@JvmOverloads`
constructor):

| Parameter | Default | Purpose |
|---|---|---|
| `mode` | `MONITOR` | `MONITOR` logs/reports only; `PROTECT` executes disruptive responses |
| `environment` | `RELEASE` | `QA` automatically disables debugger/ADB/dev-options checks |
| `enabledChecks` | `emptySet()` | allow-list of checks; empty = all enabled |
| `disabledChecks` | `emptySet()` | checks to disable |
| `thresholds` | `0.30/0.60/0.85` | LOW/MEDIUM/HIGH/CRITICAL score boundaries (see scoring) |
| `policy` | `Policy.ALERT_ONLY` | maps an assessment to a list of `Response`s |
| `telemetry` | `TelemetrySink.NOOP` | telemetry sink |
| `multiProcess` | `MAIN_ONLY` | scan engine runs only in the main process |
| `expectedSignatureSha256` | `emptySet()` | APK signer certificate pin |
| `allowedInstallers` | `emptySet()` | installer allow-list |
| `allowedAccessibilityServices` | `emptySet()` | accessibility-services allow-list |
| `hostActions` | `HostActions.NONE` | hook for `Degrade`/`Logout`/`BlockSensitiveOps` |
| `rules` | `null` | tuning from verified remote rules |
| `debugLogging` | `false` | internal logging; release builds contain no logging code at all |

Checks that need configuration (signature/installer/accessibility) report `Unknown` —
not a detection — while their lists are empty, so they never cause false accusations.

---

## Policy, responses, and silent mode

`Policy` receives a `ThreatAssessment` and returns a list of `Response`s:

| Response | Effect |
|---|---|
| `Log` | internal log (silent unless `debugLogging`) |
| `Report` | send to `TelemetrySink` |
| `Exit` | **silent kill**: native `exit_group` syscall (no stack trace/dialog/ANR). The foreground task is removed first (`finishAndRemoveTask`) and the kill is delayed briefly, so the platform does not relaunch the activity in a loop. |
| `Degrade` / `Logout` / `BlockSensitiveOps` | invoke the app's `HostActions` |
| `Custom { ... }` | arbitrary app action, on the main thread |

In `Mode.MONITOR`, disruptive responses are skipped (only `Log`, `Report`, and
`Custom` run).

Ready-made presets:

```kotlin
// Silent kill when level >= HIGH (recommended for production)
RaspConfig(mode = Mode.PROTECT, policy = Policies.silentKillOn(Level.HIGH))

// Report to telemetry first, then kill
RaspConfig(mode = Mode.PROTECT, policy = Policies.reportThenSilentKillOn(Level.HIGH))

// Custom policy
RaspConfig(policy = Policy { a ->
    when {
        a.level >= Level.CRITICAL -> listOf(Response.Report, Response.Exit)
        a.level >= Level.HIGH     -> listOf(Response.Logout)
        a.level >= Level.MEDIUM   -> listOf(Response.Degrade)
        else                      -> listOf(Response.Log)
    }
})
```

**Score → level mapping** (changeable via `thresholds` or rules): per-category score
is the *noisy-OR* of all evidence; the global score is the strongest category plus
0.05 when ≥ 2 categories are suspicious. Levels: `≥0.85` CRITICAL, `≥0.60` HIGH,
`≥0.30` MEDIUM, `>0` LOW.

---

## Telemetry (optional)

Persistent queue (JSON Lines), batching, retry backoff, redaction hook. The SDK
collects no device identifiers on its own:

```kotlin
val telemetry = QueuedTelemetrySink(
    queue = TelemetryQueue(
        store = FileTelemetryStore(File(filesDir, "telemetry.jsonl")),
        maxEvents = 100, // oldest events are dropped when full
    ),
    uploader = { events -> backend.send(events) }, // true = batch accepted
    scheduler = ExecutorTelemetryScheduler(),
    config = TelemetryQueueConfig(minLevel = Level.LOW, batchSize = 10),
    redact = { event -> event }, // return null to drop
)

RaspConfig(telemetry = telemetry)
```

---

## Signed remote rules (optional)

Rules are **data-only** JSON (not scripts) carrying tuning: disabled checks,
per-`checkId` confidence scaling, and threshold overrides. Envelopes are signed with
ECDSA P-256; the SDK verifies them against an embedded public key and ignores
expired/invalid rules (fail-open).

```kotlin
val rules = SignedRulesLoader(RuleEnvelopeVerifier(PUBLIC_KEY_BASE64))
    .loadFromUrl("https://backend.example/rules.json", System.currentTimeMillis())

RaspConfig(rules = rules)
```

On the server side (this module can be reused there):

```kotlin
val payload = RuleCodec.encode(
    RaspRules(
        version = 3,
        expiresAtMs = System.currentTimeMillis() + 7 * 24 * 3600_000,
        disabledChecks = setOf("env.developer_options"),
        confidenceScale = mapOf("integrity.installer" to 0.5f),
        thresholds = Thresholds(low = 0.3f, medium = 0.6f, high = 0.85f),
    )
)
val envelope = RuleSigner(privateKey).envelopeFor(payload) // store/serve this envelope
```

---

## Play Integrity (optional)

Verdict verification **must happen on the server**. The SDK only fetches tokens:

```kotlin
val gateway = PlayIntegrityGateway(context, cloudProjectNumber = 123456789012L)
gateway.requestToken(nonce = serverNonce) { token, error ->
    if (token != null) backend.verify(token) // backend calls the Play Integrity API
}
```

Requirements: the app is distributed through Google Play and the cloud project is
linked in Play Console.

### Key attestation (optional, hardware-backed)

The SDK can obtain a hardware-backed attestation certificate chain
(AndroidKeyStore, TEE/StrongBox) for **server-side** verification:

```kotlin
Rasp.requestKeyAttestation(serverNonce) { result ->
    if (result == null) return@requestKeyAttestation // unavailable/failed
    backend.verifyKeyAttestation(result.certificateChain, serverNonce)
    // Client-side signals (not proof): result.deviceLocked, result.verifiedBootState
}
```

Unlike `ro.boot.*` properties — which a rooted device can spoof with `resetprop` —
these values are signed by the TEE and chained to Google's roots, so the backend
should verify the chain. The built-in check `integrity.key_attestation` reads the
same fields locally as one more signal.

---

## Utilities

```kotlin
// Tapjacking: reject touches while the screen is obscured by an overlay
override fun dispatchTouchEvent(event: MotionEvent): Boolean {
    if (TouchSafety.isObscured(event)) return false
    return super.dispatchTouchEvent(event)
}

// Screen capture: protect sensitive screens
ScreenGuard.enableSecure(activity)
```

---

## Advanced customization

- **Disable specific checks**: `RaspConfig(disabledChecks = setOf("env.adb_enabled"))`
- **Lower/raise confidence without shipping an app update**: via remote rules
  (`confidenceScale`, `"0"` effectively disables).
- **Rename the native library**: `knightrasp.nativeLibName` property (see Installation).
- **Custom checks**: implement `RaspCheck`, then attach a custom runtime:
  ```kotlin
  val probes = AndroidProbes(context, JniBridge.createOrNull())
  Rasp.attachRuntime(RaspRuntimeImpl(probes, DefaultChecks.list(probes) + MyCustomCheck()))
  ```
- **Exercise the pipeline without a device**: `./gradlew :rasp:testDebugUnitTest --tests "io.knightrasp.internal.PipelineDemoTest"`

---

## Check catalog

28 checks, 7 categories — the full list with confidence, cost, and required
configuration is in [docs/CHECKS.md](docs/CHECKS.md). Summary:

| Category | Checks |
|---|---|
| ROOT | `root.su_binary`, `root.magisk_artifacts`, `root.test_keys`, `root.native_mounts`, `root.bootloader_state` |
| DEBUG | `debug.debugger_connected`, `debug.tracer_pid`, `debug.native_ptrace` |
| HOOK | `hook.frida_threads`, `hook.maps_artifacts`, `hook.native_maps`, `hook.injected_memory`, `hook.system_libraries`, `hook.plt_integrity` |
| INTEGRITY | `integrity.signature`, `integrity.installer`, `integrity.native_text`, `integrity.sdk_library_origin`, `integrity.key_attestation` |
| EMULATOR | `emulator.props`, `emulator.files`, `emulator.cpuinfo` |
| ENVIRONMENT | `env.developer_options`, `env.adb_enabled`, `env.mock_location`, `env.accessibility_services` |
| VIRTUALIZATION | `virtualization.cloner_app`, `virtualization.process_name` |

---

## Module layout

| Module | Contents |
|---|---|
| `rasp-api` | Public contracts: `Rasp`, `RaspConfig`, `RaspCheck`, `Probes`, `Policies`, utilities |
| `rasp-core` | Engine (two waves, timeout/abandon, cache), scorer, runtime, response executor |
| `rasp-probes` | Android probe implementations (file, proc, package, settings, system) |
| `rasp-native` | C++ + JNI: anti-debug/anti-hook/integrity/kill (configurable library name) |
| `rasp-testing` | Fake probes + `testContext()` for unit-testing checks |
| `rasp-telemetry` | Persistent queue + batching + retry + redaction |
| `rasp-rules` | ECDSA verification, rule parser, and loader (file/URL) |
| `rasp-playintegrity` | Play Integrity token client |
| `check-*` | Check implementations per category (7 modules) |
| `rasp` | Aggregate AAR + runtime auto-attach (what consumers depend on) |
| `sample` | Sample application (silent mode enabled) |

---

## Build & test from source

```bash
./gradlew testDebugUnitTest          # 114 unit tests (JVM, no device needed)
./gradlew :rasp:assembleRelease      # SDK AAR
./gradlew publishToMavenLocal        # publish all modules to ~/.m2
./gradlew :sample:assembleDebug      # sample app
./gradlew :sample:assembleRelease    # verifies consumer rules + R8
```

`local.properties` must contain `sdk.dir`. For the native module, make sure NDK &
CMake are installed; for a custom CMake, point `cmake.dir`.

---

## Status & roadmap

- **Phase 1** — foundation: API, engine, scoring, policy, 10 checks ✅
- **Phase 2** — native & integrity: anti-debug/anti-hook/tamper, 4 more checks ✅
- **Phase 3** — operations: telemetry, signed rules, Play Integrity, local Maven publishing ✅
- **Phase 4** — advanced: SDK anti-tamper, tapjacking, virtualization, accessibility ✅

Remaining toward commercial grade: multi-device false-positive calibration (device
farm), native obfuscation (OLLVM/string encryption) + build-time `.so` hash pinning,
Maven Central publishing, CI (unit + instrumented + benchmark), and server-side
signal correlation.

---

## Security & limitations

- RASP is **not an absolute guarantee**. An attacker with kernel/root control can
  defeat almost any detection; the goal is to raise the cost of attack, not eliminate it.
- The SDK source (open source) is readable. Keep critical decisions on the **server**
  (token validation, session revocation) and use Play Integrity at sensitive points.
- Never ship secrets/API keys inside the app — including inside this SDK.
- The engine is **fail-open**: internal errors never take the host app down.

### Hardening & anti-reverse-engineering

What is already in place:

| Layer | Measure |
|---|---|
| Kotlin/Java | Release builds contain **no logging code and no log strings** — the release logger is a compile-time no-op and every call site is gated by `const ENABLED = false`, so R8 removes them. |
| Kotlin/Java | Detection-sensitive constants (root paths, Magisk packages, hook markers, `/proc` paths, settings keys, cloner packages) are stored as **XOR+hex blobs** and decoded at runtime (`TextCodec`); no plaintext markers remain in the dex. |
| Kotlin/Java | The native library name is decoded at runtime from an obfuscated `BuildConfig` value. |
| Kotlin/Java | Consumer ProGuard rules keep **only the public contract** (`check.*`/`probe.*` use a single `*`, so internal implementations in subpackages are renamed by the host app's R8 in release builds). |
| Kotlin/Java | `TextCodec` decode functions are **`inline`**: the decoding loop is copied into every call site, so there is no single method to hook to harvest all constants at runtime. |
| Kotlin/Java | **Safety kill**: in PROTECT mode a HIGH+ verdict is also reported to the native layer, which terminates the process from its watchdog even if the policy/response path is hooked. |
| Native | **Watchdog thread**: independently re-evaluates the native checks every 5 s and terminates the process on its own — hooking `Rasp.init`, the policy, the executor, or the probe interface cannot stop it. If `init` never configures it (hooked/skipped), it arms itself in fail-secure mode. Any inline hook applied after load is caught by the periodic executable-segment re-check. |
| Native | **Build-time pinned digest**: CMake strips the library and fills a `.krpin` slot with the FNV-1a digest of the executable segment (`pin_digest.py`). At runtime the mapped segment is hashed and compared, so patching the `.so` **before it is ever loaded** (Frida gadget/spawn, repackaged library) is detected — not just post-load hooks. |
| Native | Sensitive C++ strings (paths, markers, JNI class name) are **compile-time XOR-encrypted** and never appear in `.rodata`. |
| Native | JNI methods are bound with **`RegisterNatives`** in `JNI_OnLoad` — no `Java_*` symbols are exported (only `JNI_OnLoad`), so symbol-based fingerprinting and hook targeting get harder. |
| Native | The library identifies its own module via **`dladdr()`**, so no file-name string is needed internally. |
| Native | Linker hardening: **full RELRO + `-z now`**, non-executable stack, `--exclude-libs,ALL`, hidden visibility; debug symbols are stripped by AGP in release. |
| Native | Raw syscalls on arm64 for the integrity-critical reads (`/proc/self/status`, `/proc/self/maps`). |

Honest limitations:

- There is **no packer** (encrypted-dex/loader). Debug builds and DWARF sections still
  contain plaintext and source paths — only release artifacts are hardened.
- `<queries>` entries in the manifest necessarily list the package names of known root
  managers/cloners (required by the platform's package-visibility rules).
- Obfuscation prevents casual static analysis, not a determined attacker. Remember:
  **client-side checks are advisory** — back every serious decision with server-side
  verification.

---

## Privacy

The SDK collects no device identifiers. Anything you add to `TelemetryEvent`/the
redactor is the host app's responsibility under its privacy policy (Play Data Safety,
GDPR, Indonesia's PDP Law).

---

## License

[MIT](LICENSE) © 2026 KnightRASP contributors
