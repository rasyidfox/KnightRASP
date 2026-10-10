package io.knightrasp.check.virtualization

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.PackageProbe
import io.knightrasp.util.ObfuscatedStrings

/**
 * Installed app-cloner / parallel-space hosts. Their presence does not automatically
 * mean our app runs inside one (many legitimate users have them), so this is a weak
 * signal best combined with `virtualization.process_name` or other anomalies.
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

        /** Obfuscated app-cloner / parallel-space host packages. */
        val CLONER_PACKAGES: List<String> = ObfuscatedStrings.decodeList(
            "202c2e6d2f21266d332231222f2f262f49202c2e6d2f21266d332231222f2f262f6d2a2d372f49202c2e6d26" +
                "3b20262f2f2a222d20266d2e362f372a2220202c362d373049202c2e6d263b20262f2f2a222d20266d2736" +
                "222f222a2749202c2e6d332c2f26303722316d272c2e362f372a332f2649202c2e6d332c2f26303722316d" +
                "3036332631202f2c2d2649202c2e6d332231222f2f262f6d30332220266d2f2a3726",
            0x43,
        )
    }
}
