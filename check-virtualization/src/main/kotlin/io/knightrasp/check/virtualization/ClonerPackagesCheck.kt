package io.knightrasp.check.virtualization

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.PackageProbe

/**
 * Host app cloner / parallel space yang terpasang. Keberadaannya tidak otomatis berarti
 * aplikasi kita berjalan di dalamnya (banyak pengguna sah memakainya), jadi ini sinyal
 * lemah yang sebaiknya digabung dengan `virtualization.process_name` atau anomali lain.
 */
class ClonerPackagesCheck(private val packages: PackageProbe) : RaspCheck {

    override val id = "virtualization.cloner_app"
    override val category = Category.VIRTUALIZATION
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val found = CLONER_PACKAGES.filter(packages::isInstalled)
        return if (found.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(found.map { Evidence(id, CONFIDENCE, "pkg:$it") })
        }
    }

    companion object {
        const val CONFIDENCE = 0.35f

        val CLONER_PACKAGES = listOf(
            "com.lbe.parallel",
            "com.lbe.parallel.intl",
            "com.excelliance.multiaccounts",
            "com.excelliance.dualaid",
            "com.polestar.domultiple",
            "com.polestar.superclone",
            "com.parallel.space.lite",
        )
    }
}
