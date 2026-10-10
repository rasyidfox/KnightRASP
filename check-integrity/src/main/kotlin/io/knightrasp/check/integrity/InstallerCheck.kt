package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.PackageProbe

/**
 * Memeriksa asal instalasi. Sideload (tanpa installer) atau installer di luar daftar
 * [RaspContext.config] adalah sinyal lemah-menengah: banyak pengguna sah memasang APK
 * secara manual, jadi jangan jadikan bukti tunggal.
 *
 * Bila `allowedInstallers` kosong, check melaporkan Unknown.
 */
class InstallerCheck(private val packages: PackageProbe) : RaspCheck {

    override val id = "integrity.installer"
    override val category = Category.INTEGRITY
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val allowed = ctx.config.allowedInstallers.filter { it.isNotBlank() }.toSet()
        if (allowed.isEmpty()) {
            return CheckResult.Unknown("allowedInstallers belum dikonfigurasi")
        }

        val installer = packages.installerPackageName(ctx.packageName)
            ?: return CheckResult.Detected(
                listOf(Evidence(id, SIDELOAD_CONFIDENCE, "tidak ada installer (sideload)"))
            )

        return if (installer in allowed) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(
                listOf(Evidence(id, UNKNOWN_INSTALLER_CONFIDENCE, "installer:$installer"))
            )
        }
    }

    companion object {
        const val SIDELOAD_CONFIDENCE = 0.5f
        const val UNKNOWN_INSTALLER_CONFIDENCE = 0.6f
    }
}
