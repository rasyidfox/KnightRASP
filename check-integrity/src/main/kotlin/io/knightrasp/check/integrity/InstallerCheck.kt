package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.PackageProbe

/**
 * Checks the installation source. Sideload (no installer) or an installer outside
 * the list in [RaspContext.config] is a weak-to-medium signal: many legitimate users
 * install APKs manually, so do not treat it as sole evidence.
 *
 * When `allowedInstallers` is empty, the check reports Unknown.
 */
class InstallerCheck(private val packages: PackageProbe) : RaspCheck {

    override val id = "integrity.installer"
    override val category = Category.INTEGRITY
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val allowed = ctx.config.allowedInstallers.filter { it.isNotBlank() }.toSet()
        if (allowed.isEmpty()) {
            return CheckResult.Unknown("allowedInstallers not configured")
        }

        val installer = packages.installerPackageName(ctx.packageName)
            ?: return CheckResult.Detected(
                listOf(Evidence(id, SIDELOAD_CONFIDENCE, "no installer (sideload)"))
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
