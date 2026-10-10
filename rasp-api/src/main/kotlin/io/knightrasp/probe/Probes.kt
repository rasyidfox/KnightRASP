package io.knightrasp.probe

/**
 * Collection of probes — the only channel checks have to access the OS.
 * Production implementations live in the `rasp-probes` module; tests use fakes.
 */
interface Probes {
    val file: FileProbe
    val proc: ProcProbe
    val packages: PackageProbe
    val settings: SettingsProbe
    val system: SystemProbe

    /** Native probe; null when the native library is unavailable (e.g. NDK-less variant). */
    val native: NativeProbe?

    /** Hardware key attestation; null when unavailable (e.g. API < 24, no TEE). */
    val attestation: AttestationProbe?
}

/**
 * Hardware-backed key attestation (AndroidKeyStore). Implementations must
 * generate an ephemeral attested key per call (the challenge is only honored at
 * key generation) and delete it afterwards.
 */
interface AttestationProbe {
    /**
     * Generates an attested key for [nonce] and returns the certificate chain.
     * Null when attestation is unavailable or fails.
     */
    fun attest(nonce: String?): io.knightrasp.model.KeyAttestationResult?
}

interface FileProbe {
    fun exists(path: String): Boolean

    /** File contents as UTF-8, or null when unreadable. */
    fun read(path: String): String?
}

interface ProcProbe {
    /** Contents of /proc/self/status, or null on failure. */
    fun selfStatus(): String?

    /** Contents of /proc/self/maps, or null on failure. */
    fun selfMaps(): String?

    /** Process name from /proc/self/cmdline, or null on failure. */
    fun selfCmdline(): String?

    /** Thread names of this process (from /proc/self/task/&lt;tid&gt;/comm). */
    fun threadNames(): List<String>
}

interface PackageProbe {
    /**
     * Whether the package is installed and visible to the app.
     * Note: on Android 11+ visibility is restricted; check modules declare
     * `<queries>` for the packages they inspect.
     */
    fun isInstalled(packageName: String): Boolean

    /** SHA-256 (hex, lowercase) of the package signing certificate. */
    fun signingCertSha256(packageName: String): List<String>

    /** Installer package (e.g. com.android.vending), or null when sideloaded. */
    fun installerPackageName(packageName: String): String?

    /** Installed APK path (sourceDir) of the package, or null when unreadable. */
    fun apkPath(packageName: String): String?
}

interface SettingsProbe {
    fun globalInt(key: String, default: Int): Int

    fun secureInt(key: String, default: Int): Int
}

/** Device properties & basic runtime state. */
interface SystemProbe {
    val manufacturer: String
    val brand: String
    val model: String
    val device: String
    val product: String
    val hardware: String
    val fingerprint: String
    val tags: String
    val supportedAbis: List<String>
    val sdkInt: Int

    fun isDebuggerConnected(): Boolean

    /** Ids of enabled accessibility services (format `package/class`). */
    fun enabledAccessibilityServiceIds(): List<String>
}

/**
 * A probe that runs in C/C++ via JNI. Used for checks that cannot be trusted
 * when run entirely in the Java layer.
 */
interface NativeProbe {
    /**
     * File name of the loaded native library, e.g. `libguardcore.so`.
     * Used by anti-tamper checks to recognize the SDK's own mappings.
     */
    val moduleName: String

    /** true = the process shows signs of ptrace / debug from the native layer. */
    fun signalA(): Boolean

    /** true = the native library executable segment changed from baseline (patching indication). */
    fun signalC(): Boolean

    /** true = hook artifacts (frida/xposed/substrate) seen when reading /proc/self/maps. */
    fun signalB(): Boolean

    /** true = root-framework artifacts are visible in the process mount namespace. */
    fun signalD(): Boolean

    /** true = verified-boot / bootloader state indicates a modified device. */
    fun signalE(): Boolean

    /** true = memory-map shapes typical of injected agents (memfd / writable+exec mappings). */
    fun signalF(): Boolean

    /** true = a watched system library's executable segment differs from the on-disk file. */
    fun signalG(): Boolean

    /** true = a watched PLT/GOT entry in our own library was redirected after load. */
    fun signalH(): Boolean

    /**
     * Enables and configures the native watchdog: a native thread that keeps
     * re-evaluating the native checks independently of the Kotlin engine and can
     * terminate the process on its own. If this is never called (init hooked or
     * skipped), the watchdog arms itself in fail-secure mode.
     */
    fun watchdog(enabled: Boolean, killOnEvidence: Boolean, intervalMs: Int)

    /**
     * Reports a high-risk verdict from the evaluator to the native layer. The
     * native side latches it; the Kotlin response path performs the actual
     * termination (so the foreground task can be removed first), and the watchdog
     * acts as a last resort if Kotlin never does.
     */
    fun signalRisk(detected: Boolean)

    /** Kills the process via a raw syscall, bypassing Java/libc wrappers. */
    fun shutdown()
}
