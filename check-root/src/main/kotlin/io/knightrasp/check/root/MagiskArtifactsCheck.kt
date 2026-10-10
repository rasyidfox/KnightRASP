package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.FileProbe
import io.knightrasp.probe.PackageProbe

/**
 * Artefak Magisk/KernelSU/LSPosed: direktori data dan paket manager.
 * Direktori `/data/adb` (magisk/ksu) umumnya hanya ada pada perangkat dengan root modern.
 */
class MagiskArtifactsCheck(
    private val files: FileProbe,
    private val packages: PackageProbe,
) : RaspCheck {

    override val id = "root.magisk_artifacts"
    override val category = Category.ROOT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val evidence = mutableListOf<Evidence>()
        files.let { probe ->
            MAGISK_PATHS.filter(probe::exists).forEach { path ->
                evidence += Evidence(id, PATH_CONFIDENCE, path)
            }
        }
        packages.let { probe ->
            ROOT_MANAGER_PACKAGES.filter(probe::isInstalled).forEach { pkg ->
                evidence += Evidence(id, PACKAGE_CONFIDENCE, "pkg:$pkg")
            }
        }
        return if (evidence.isEmpty()) CheckResult.Clean else CheckResult.Detected(evidence)
    }

    companion object {
        const val PATH_CONFIDENCE = 0.7f
        const val PACKAGE_CONFIDENCE = 0.5f

        val MAGISK_PATHS = listOf(
            "/data/adb/magisk",
            "/data/adb/modules",
            "/sbin/.magisk",
            "/sbin/.core",
            "/data/adb/ksu",
        )

        val ROOT_MANAGER_PACKAGES = listOf(
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "org.lsposed.manager",
            "eu.chainfire.supersu",
        )
    }
}
