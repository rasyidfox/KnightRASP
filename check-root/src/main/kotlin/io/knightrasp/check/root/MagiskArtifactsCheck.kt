package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.FileProbe
import io.knightrasp.probe.PackageProbe
import io.knightrasp.util.TextCodec

/**
 * Magisk/KernelSU/LSPosed artifacts: data directories and manager packages.
 * The `/data/adb` directory (magisk/ksu) usually exists only on devices with modern root.
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

        /** Obfuscated constants (see SuBinaryCheck). */
        val MAGISK_PATHS: List<String> = TextCodec.decodeList(
            "743f3a2f3a743a3f3974363a3c32283051743f3a2f3a743a3f397436343f2e373e28517428393235747536" +
                "3a3c32283051742839323574753834293e51743f3a2f3a743a3f397430282e",
            0x5B,
        )

        val ROOT_MANAGER_PACKAGES: List<String> = TextCodec.decodeList(
            "121e1c5f051e011b1e191f06045f1c101618021a7b1c145f0614180219045f1a14031f141d02047b1e0316" +
                "5f1d02011e0214155f1c101f101614037b14045f121910181f171803145f02040114030204",
            0x71,
        )
    }
}
