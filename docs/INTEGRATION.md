# Integration Guide

How to embed **KnightRASP** into an existing Android app. This is the practical
companion to the [README](../README.md): installation, initialization, mode/policy
rollout, Java interop, production pins, and how to verify enforcement on a device.

The snippets were verified against real host projects:

- Kotlin host — the bundled [`sample`](../sample) app (AGP 8.13 / Gradle 8.14).
- Java host — a Gradle **Groovy DSL** project with a Java `Application` class,
  built with **AGP 9.4.1 / Gradle 9.8.0** (the Java example below compiles as-is).

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Add the SDK dependency](#2-add-the-sdk-dependency)
3. [Initialize in your `Application` class](#3-initialize-in-your-application-class)
4. [Choose a mode and policy](#4-choose-a-mode-and-policy)
5. [Java interop cheat sheet](#5-java-interop-cheat-sheet)
6. [Production checklist](#6-production-checklist)
7. [Verify the integration on a device](#7-verify-the-integration-on-a-device)
8. [Troubleshooting / FAQ](#8-troubleshooting--faq)

---

## 1. Prerequisites

| Requirement | Value |
|---|---|
| Host app `minSdk` | **23+** |
| JDK | 17+ (full JDK, not a JRE) |
| AGP / Gradle | tested with AGP 8.13 / Gradle 8.14 **and** AGP 9.4 / Gradle 9.8 |
| AndroidX | not required. Only `rasp-playintegrity` needs `android.useAndroidX=true` |
| NDK | **not required by the host.** The SDK ships prebuilt `.so` for `arm64-v8a`, `armeabi-v7a`, `x86_64` |

The SDK is published as one AAR per module, group `io.knightrasp`, version `0.1.0`.

---

## 2. Add the SDK dependency

### 2.1 Publish the SDK to your local Maven

```bash
git clone https://github.com/rasyidfox/KnightRASP.git
cd KnightRASP
./gradlew publishToMavenLocal     # writes io.knightrasp:*:0.1.0 into ~/.m2/repository
```

### 2.2 Allow `mavenLocal()` in the host project

Repositories must be declared in **settings**, not in the app module (projects that
use `RepositoriesMode.FAIL_ON_PROJECT_REPOS` will reject the build otherwise).

Kotlin DSL — `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        mavenLocal()   // <- add this
    }
}
```

Groovy — `settings.gradle`:

```groovy
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        mavenLocal()   // <- add this
    }
}
```

### 2.3 Declare the dependency

Kotlin DSL — `app/build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.knightrasp:rasp:0.1.0")              // required: checks + native core

    // Optional modules:
    implementation("io.knightrasp:rasp-telemetry:0.1.0")    // file-backed telemetry queue
    implementation("io.knightrasp:rasp-rules:0.1.0")        // signed remote rules
    // implementation("io.knightrasp:rasp-playintegrity:0.1.0") // needs android.useAndroidX=true
}
```

Groovy — `app/build.gradle`:

```groovy
dependencies {
    implementation 'io.knightrasp:rasp:0.1.0'

    // implementation 'io.knightrasp:rasp-telemetry:0.1.0'
    // implementation 'io.knightrasp:rasp-rules:0.1.0'
    // implementation 'io.knightrasp:rasp-playintegrity:0.1.0'
}
```

All transitive modules (`rasp-api`, `rasp-core`, `rasp-probes`, `rasp-native`,
`rasp-checks-*`) arrive automatically through the POM. **No manual ProGuard/R8 rules
are needed** — consumer rules ship inside the AARs.

### 2.4 Composite build alternative (no publishing)

If you keep the SDK checkout next to your app, substitute the published artifacts
with the source projects:

```kotlin
// settings.gradle.kts
includeBuild("../KnightRASP")
```

```groovy
// settings.gradle
includeBuild '../KnightRASP'
```

Then use the same coordinates (`io.knightrasp:rasp:0.1.0`) — Gradle substitutes them.

---

## 3. Initialize in your `Application` class

Call `Rasp.init(...)` **once** from `Application.onCreate()`. The aggregate `rasp`
module attaches the runtime through a `ContentProvider`, so there is no other
registration step.

### 3.1 Kotlin

```kotlin
import android.app.Application
import io.knightrasp.Rasp
import io.knightrasp.RaspListener
import io.knightrasp.config.Mode
import io.knightrasp.config.Policies
import io.knightrasp.config.RaspConfig
import io.knightrasp.model.Level
import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment

class App : Application() {
    override fun onCreate() {
        super.onCreate()

        Rasp.init(
            this,
            RaspConfig(
                // Start with MONITOR while you measure; PROTECT enforces.
                mode = Mode.PROTECT,
                policy = Policies.silentKillOn(Level.HIGH),
                // Production pins (see §6):
                // expectedSignatureSha256 = setOf("<sha256 of your signing cert>"),
                // allowedInstallers = setOf("com.android.vending"),
                debugLogging = false,     // keep false: enforcement must stay silent
            ),
        )

        Rasp.addListener(object : RaspListener {
            override fun onAssessment(result: ThreatAssessment) {
                // Send level/score/categories/evidence to your backend.
                // This is application logging — the SDK itself writes nothing.
            }

            override fun onError(error: RaspError) {
                // The engine is fail-open: report internal errors and keep running.
            }
        })

        Rasp.scan()                         // async; deliver results via the listener
        // val assessment = Rasp.scanSync(2_000)   // synchronous gate for critical flows
    }
}
```

### 3.2 Java

```java
import android.app.Application;

import java.util.Collections;

import io.knightrasp.Rasp;
import io.knightrasp.RaspListener;
import io.knightrasp.config.Environment;
import io.knightrasp.config.Mode;
import io.knightrasp.config.Policies;
import io.knightrasp.config.RaspConfig;
import io.knightrasp.config.Thresholds;
import io.knightrasp.model.Level;
import io.knightrasp.model.RaspError;
import io.knightrasp.model.ThreatAssessment;

public class App extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        RaspConfig config = new RaspConfig(
                Mode.PROTECT,                                // MONITOR while tuning
                Environment.RELEASE,
                Collections.<String>emptySet(),              // enabledChecks (empty = all)
                Collections.<String>emptySet(),              // disabledChecks
                new Thresholds(),                            // or new Thresholds(0.30f, 0.60f, 0.85f)
                Policies.INSTANCE.silentKillOn(Level.HIGH)); // policy

        Rasp.init(this, config);

        Rasp.addListener(new RaspListener() {
            @Override
            public void onAssessment(ThreatAssessment result) {
                // Transport to your backend here.
            }

            @Override
            public void onError(RaspError error) {
                // Fail-open: report and continue.
            }
        });

        Rasp.scan();                          // async
        // ThreatAssessment now = Rasp.scanSync(2_000L);   // sync gate where needed
    }
}
```

### 3.3 Notes

- `Rasp.scan()` runs with `Trigger.ON_DEMAND`; use `Rasp.scan(Trigger.ON_FOREGROUND)`
  for lifecycle-driven runs. `Trigger`: `ON_INIT`, `ON_FOREGROUND`, `ON_DEMAND`,
  `PERIODIC`.
- `Rasp.scanSync(timeoutMs)` blocks the calling thread — never call it on the main
  thread in production paths.
- `MAIN_ONLY` is the default: in apps with extra processes, the engine runs only in
  the main process. Use `MultiProcessMode.ALL` if every process must be covered.
- `debugLogging = true` only works in debug builds; release builds contain no
  logging code at all.

---

## 4. Choose a mode and policy

`Mode` decides **whether** disruptive responses execute; `Policy` decides **which**
responses a given assessment requests.

| | `Mode.MONITOR` | `Mode.PROTECT` |
|---|---|---|
| `Log`, `Report`, `Custom` | executed | executed |
| `Exit`, `Degrade`, `Logout`, `BlockSensitiveOps` | **skipped** | executed |

This is the most common integration surprise: **an app that never force-closes on a
rooted device is (correctly) in `MONITOR`, or the policy never returns `Response.Exit`.**
Silent kill requires both `Mode.PROTECT` **and** a policy that maps the level to
`Exit` — e.g. `Policies.silentKillOn(Level.HIGH)`.

Recommended rollout:

| Stage | Mode | Policy | Purpose |
|---|---|---|---|
| Development | `MONITOR` | `Policy.ALERT_ONLY` | measure signals, zero disruption |
| Field trial | `PROTECT` | `Policies.reportThenSilentKillOn(Level.HIGH)` | collect evidence, then enforce |
| Production | `PROTECT` | `Policies.silentKillOn(Level.HIGH)` | silent enforcement |

> **Dev-device gotcha.** On a rooted device, an emulator, or any device with
> developer options/ADB enabled, a `PROTECT + silentKillOn(HIGH)` build closes itself
> within the first second — by design, with no dialog and no crash log. While
> developing, keep debug builds in `MONITOR`, or disable the noisy checks
> (`disabledChecks = setOf("env.adb_enabled", "env.developer_options", …)`).
> `Environment.QA` automatically disables the development-time checks
> (`env.adb_enabled`, `env.developer_options`, `debug.debugger_connected`,
> `debug.tracer_pid`, `debug.native_ptrace`) but **not** root/hook/integrity.

Enforcement is executed natively (`exit_group`) even if the Kotlin policy path is
hooked: in `PROTECT` mode a `HIGH+` verdict also latches the native safety kill, and
the foreground task is removed first so Android does not relaunch the activity.

---

## 5. Java interop cheat sheet

The API is Kotlin-first but fully usable from Java:

| Kotlin | Java |
|---|---|
| `Rasp.init(app, config)` (all `Rasp` members are `@JvmStatic`) | `Rasp.init(app, config)` — no `Rasp.INSTANCE` needed |
| `Policies.silentKillOn(Level.HIGH)` (`object`) | `Policies.INSTANCE.silentKillOn(Level.HIGH)` |
| `RaspConfig(mode, environment, enabled, disabled, thresholds, policy, …)` | `@JvmOverloads` generates overloads from 0 up to all 16 parameters; **`policy` is the 6th parameter**, so the shortest constructor that sets a policy is the 6-argument one shown above |
| `Thresholds()` / `Thresholds(0.30f, 0.60f, 0.85f)` | both work from Java: `new Thresholds()` (Kotlin emits a no-arg constructor because every parameter has a default) or `new Thresholds(low, medium, high)` |
| `scan()` / `scan(Trigger)` | same, call directly |
| `scanSync(2_000)` | `Rasp.scanSync(2_000L)` |
| `addListener { … }` | `RaspListener` has **default methods**, so a Java anonymous class may override only `onAssessment`, only `onError`, or both |
| `requestKeyAttestation(nonce) { result -> … }` | `Rasp.requestKeyAttestation(nonce, result -> { … })` — the callback is a SAM interface (`KeyAttestationCallback`) |
| `RaspRules(...)` | Kotlin data class without `@JvmOverloads`: Java must pass **all** arguments positionally (see `RaspRules` in `rasp-api`) |
| `HostActions`, telemetry sinks | interfaces — implement (or use the provided `HostActions.NONE` / `TelemetrySink.NOOP` constants) |

Enums from Java:

- `Mode`: `MONITOR`, `PROTECT`
- `Environment`: `RELEASE`, `QA`
- `Level`: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `Trigger`: `ON_INIT`, `ON_FOREGROUND`, `ON_DEMAND`, `PERIODIC`
- `Category`: `ROOT`, `HOOK`, `DEBUG`, `EMULATOR`, `INTEGRITY`, `ENVIRONMENT`, `NETWORK`, `VIRTUALIZATION`

---

## 6. Production checklist

- **Signature pin.** Compute the SHA-256 of your signing certificate and pass it as
  `expectedSignatureSha256` (lowercase hex, no colons):

  ```bash
  apksigner verify --print-certs app-release.apk | grep "SHA-256 digest"
  ```

  If you use Play App Signing, pin the **Play signing certificate**, not the upload
  key. While the set is empty the check reports `Unknown` (never a false detection).
- **Installer allow-list.** `allowedInstallers = setOf("com.android.vending", …)` —
  empty means `Unknown`.
- **Accessibility allow-list.** `allowedAccessibilityServices` accepts
  `package/class` ids such as `com.google.android.marvin.talkback/.TalkBackService`.
- **Thresholds / rules.** Tune `thresholds` or ship signed remote rules
  (`confidenceScale`, `disabledChecks`) without an app update.
- **Debug build hygiene.** Keep `debugLogging = false` in release; do not put API
  keys or trust decisions in the AAR — the client is attacker-controlled.
- **Server-side is what makes it strong.** Forward assessments via telemetry or your
  own listener and make decisions on the backend; verify the **key attestation
  chain** (`Rasp.requestKeyAttestation`, single-use nonce) and the **Play Integrity
  verdict** server-side. Client signals alone can be spoofed on a rooted device.

See the README sections *Telemetry*, *Signed remote rules*, *Play Integrity*, and
*Key attestation* for API details.

---

## 7. Verify the integration on a device

### Enforcement smoke test (rooted device or emulator)

```bash
adb install -r app/build/outputs/apk/release/app-release.apk
adb logcat -c
adb shell monkey -p <your.package> -c android.intent.category.LAUNCHER 1
sleep 5
adb shell pidof <your.package>            # empty  -> silent kill worked
adb shell dumpsys window | grep mCurrentFocus   # focus back on the launcher
adb logcat -d | grep -E "AndroidRuntime|ANR"    # no FATAL/ANR from your app
```

### Expected results

| Scenario | Expected |
|---|---|
| `MONITOR` on a rooted device | app stays alive; listener receives `CRITICAL`/`HIGH` assessments with evidence |
| `PROTECT + silentKillOn(HIGH)` on a rooted device | process gone within ~1 s of the verdict; **no** crash dialog, **no** `AndroidRuntime` FATAL, no relaunch loop |
| `PROTECT` on a clean device | app runs normally; no kill, no false positives |
| Policy not firing | check you are not in `MONITOR` and that the policy returns `Response.Exit` |

A real verdict on a Magisk-rooted Android 13 device looks like this:

```
level=CRITICAL score=0.95 categories={ROOT=0.9, ENVIRONMENT=0.58, INTEGRITY=0.8}
  root.su_binary        0.6  /system/bin/su
  root.native_mounts    0.5  root mounts visible in the mount namespace
  root.bootloader_state 0.5  verified-boot state indicates a modified boot image
  env.developer_options 0.3  development settings enabled
  env.adb_enabled       0.4  adb enabled
  integrity.key_attestation 0.6  deviceLocked=false (hardware attestation)
  integrity.key_attestation 0.5  verifiedBootState=2 (hardware attestation)
```

The lines above came from an **app-side listener**; the SDK's own kill path produced
no log output at all.

---

## 8. Troubleshooting / FAQ

| Symptom | Cause / fix |
|---|---|
| App does not close on a rooted device | By design in `MONITOR`, or the policy returns no `Exit`. Use `Mode.PROTECT` + `Policies.silentKillOn(Level.HIGH)` |
| App closes instantly on *my* dev device | Expected in `PROTECT`: rooted/emulator/ADB/developer-options signals. Use `MONITOR` for debug builds or `Environment.QA` (does not disable root/hook/integrity checks) |
| No SDK logs anywhere | By design. Release builds contain no logging code. Use a `RaspListener` or telemetry |
| `RaspListener` never called | `Rasp.scan()` was not invoked, or the runtime failed to attach (watch `onError`). Check Logcat for your own tags only — the SDK is silent |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | The previously installed build was signed with a different key — uninstall it first |
| `mavenLocal()` seems ignored | Repositories are pinned by `RepositoriesMode.FAIL_ON_PROJECT_REPOS`: declare it in `settings.gradle(.kts)` |
| R8/ProGuard warnings mentioning `io.knightrasp` | Consumer rules ship in the AARs — no manual rules are needed. Stale warnings usually mean the dependency was not resolved |
| Kotlin stdlib version conflict | The SDK declares the stdlib as an `api` dependency; Gradle resolves the highest version requested by the app |
| Detection works in debug but not release | Check the signature pin: `integrity.signature` reports `Unknown` (not a detection) when `expectedSignatureSha256` is empty, and a mismatch is a real detection — make sure the pinned value matches the release signer |

---

## Related documentation

- [README](../README.md) — configuration table, policy presets, telemetry, signed
  rules, Play Integrity, key attestation, hardening notes.
- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout, engine and scoring design,
  native layer, threat model.
- [CHECKS.md](CHECKS.md) — all 28 checks with ids, categories, costs and expected
  confidence, useful when deciding which evidence to act on in your backend.
