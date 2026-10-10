package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe
import io.knightrasp.probe.PackageProbe
import io.knightrasp.probe.ProcProbe

/**
 * SDK anti-tamper: ensures the SDK native library (file name from
 * [io.knightrasp.probe.NativeProbe.moduleName]) is loaded from the **APK
 * installation directory** of the app (not another path such as `/data/local/tmp`) — a common
 * pattern when a native library is replaced with a patched version.
 *
 * Uses the installation directory prefix (not the exact APK path) so it stays correct for
 * apps installed from Play with per-ABI split APKs (`split_config.*.apk`).
 *
 * Complements `integrity.native_text` (patch detection after load) and
 * `integrity.signature` (APK repackaging detection).
 */
class SdkLibraryOriginCheck(
    private val proc: ProcProbe,
    private val packages: PackageProbe,
    private val native: NativeProbe?,
) : RaspCheck {

    override val id = "integrity.sdk_library_origin"
    override val category = Category.INTEGRITY
    override val cost = Cost.MEDIUM

    override fun run(ctx: RaspContext): CheckResult {
        if (native == null) {
            return CheckResult.Unknown("native probe unavailable")
        }
        val apkPath = packages.apkPath(ctx.packageName)
            ?: return CheckResult.Unknown("APK path unreadable")
        val maps = proc.selfMaps()
            ?: return CheckResult.Unknown("maps unreadable")

        val libraryName = native.moduleName
        val installDir = apkPath.substringBeforeLast('/', missingDelimiterValue = apkPath)
        if (libraryName !in maps) {
            return CheckResult.Unknown("$libraryName not found in maps")
        }

        // Direct substring search (without splitting maps into lines).
        return if (installDir in maps) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "native library loaded from outside the app directory"))
            )
        }
    }

    companion object {
        const val CONFIDENCE = 0.85f
    }
}
