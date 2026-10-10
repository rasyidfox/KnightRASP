package io.knightrasp.testing

import io.knightrasp.probe.FileProbe
import io.knightrasp.probe.NativeProbe
import io.knightrasp.probe.PackageProbe
import io.knightrasp.probe.ProcProbe
import io.knightrasp.probe.Probes
import io.knightrasp.probe.SettingsProbe
import io.knightrasp.probe.SystemProbe

/**
 * Fake probes for unit-testing checks without a device.
 *
 * All defaults model a "clean device": no files, no installed packages,
 * default settings, neutral build properties.
 */

class TestFileProbe : FileProbe {
    private val files = LinkedHashMap<String, String>()

    fun add(path: String, content: String = "") {
        files[path] = content
    }

    fun remove(path: String) {
        files.remove(path)
    }

    fun clear() = files.clear()

    override fun exists(path: String): Boolean = files.containsKey(path)

    override fun read(path: String): String? = files[path]
}

class TestProcProbe : ProcProbe {
    var status: String? = null
    var maps: String? = null
    var cmdline: String? = null
    var threads: List<String> = emptyList()

    override fun selfStatus(): String? = status

    override fun selfMaps(): String? = maps

    override fun selfCmdline(): String? = cmdline

    override fun threadNames(): List<String> = threads
}

class TestPackageProbe : PackageProbe {
    val installed = LinkedHashSet<String>()
    val signingCerts = LinkedHashMap<String, List<String>>()
    val installers = LinkedHashMap<String, String>()
    val apkPaths = LinkedHashMap<String, String>()

    override fun isInstalled(packageName: String): Boolean = packageName in installed

    override fun signingCertSha256(packageName: String): List<String> =
        signingCerts[packageName] ?: emptyList()

    override fun installerPackageName(packageName: String): String? = installers[packageName]

    override fun apkPath(packageName: String): String? = apkPaths[packageName]
}

class TestSettingsProbe : SettingsProbe {
    val global = LinkedHashMap<String, Int>()
    val secure = LinkedHashMap<String, Int>()

    override fun globalInt(key: String, default: Int): Int = global[key] ?: default

    override fun secureInt(key: String, default: Int): Int = secure[key] ?: default
}

class TestSystemProbe : SystemProbe {
    override var manufacturer = "Test"
    override var brand = "test"
    override var model = "test"
    override var device = "test"
    override var product = "test"
    override var hardware = "test"
    override var fingerprint = "test/test/test:14/UP1A/1:user/release-keys"
    override var tags = "release-keys"
    override var supportedAbis: List<String> = listOf("arm64-v8a")
    override var sdkInt = 34

    var debuggerConnected = false
    var accessibilityServices: List<String> = emptyList()

    override fun isDebuggerConnected(): Boolean = debuggerConnected

    override fun enabledAccessibilityServiceIds(): List<String> = accessibilityServices
}

/** Fake [NativeProbe]; everything defaults to negative (clean device). */
class TestNativeProbe : NativeProbe {
    override var moduleName: String = "libguardcore.so"
    var debuggerDetected = false
    var textModified = false
    var hooked = false
    var killCalled = false

    override fun signalA(): Boolean = debuggerDetected

    override fun signalC(): Boolean = textModified

    override fun signalB(): Boolean = hooked

    override fun shutdown() {
        killCalled = true
    }
}

class TestProbes(
    override val native: NativeProbe? = TestNativeProbe(),
) : Probes {
    override val file = TestFileProbe()
    override val proc = TestProcProbe()
    override val packages = TestPackageProbe()
    override val settings = TestSettingsProbe()
    override val system = TestSystemProbe()
}
