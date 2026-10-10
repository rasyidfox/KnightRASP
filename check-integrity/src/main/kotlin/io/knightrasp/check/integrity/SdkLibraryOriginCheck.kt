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
 * Anti-tamper SDK: memastikan library native SDK (nama file dari
 * [io.knightrasp.probe.NativeProbe.libraryFileName]) yang dimuat berasal dari **direktori
 * instalasi APK** aplikasi (bukan path lain seperti `/data/local/tmp`) — pola umum saat
 * library native diganti versi yang sudah di-patch.
 *
 * Menggunakan prefiks direktori instalasi (bukan path APK persis) agar tetap benar untuk
 * aplikasi yang dipasang dari Play dengan split APK per-ABI (`split_config.*.apk`).
 *
 * Melengkapi `integrity.native_text` (deteksi patch setelah load) dan
 * `integrity.signature` (deteksi repackaging APK).
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
            return CheckResult.Unknown("native probe tidak tersedia")
        }
        val apkPath = packages.apkPath(ctx.packageName)
            ?: return CheckResult.Unknown("path APK tidak terbaca")
        val maps = proc.selfMaps()
            ?: return CheckResult.Unknown("tidak bisa membaca /proc/self/maps")

        val libraryName = native.libraryFileName
        val installDir = apkPath.substringBeforeLast('/', missingDelimiterValue = apkPath)
        if (libraryName !in maps) {
            return CheckResult.Unknown("$libraryName tidak ditemukan di maps")
        }

        // Pencarian substring langsung (tanpa memecah maps menjadi baris).
        return if (installDir in maps) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "library native dimuat dari luar direktori aplikasi"))
            )
        }
    }

    companion object {
        const val CONFIDENCE = 0.85f
    }
}
