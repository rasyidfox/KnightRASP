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

    /** Kills the process via a raw syscall, bypassing Java/libc wrappers. */
    fun shutdown()
}
