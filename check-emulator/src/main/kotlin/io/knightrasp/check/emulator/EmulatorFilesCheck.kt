package io.knightrasp.check.emulator

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.FileProbe
import io.knightrasp.util.ObfuscatedStrings

/** Typical QEMU/Genymotion emulator device files. */
class EmulatorFilesCheck(private val files: FileProbe) : RaspCheck {

    override val id = "emulator.files"
    override val category = Category.EMULATOR
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val found = EMULATOR_PATHS.filter(files::exists)
        return if (found.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(found.map { Evidence(id, CONFIDENCE, it) })
        }
    }

    companion object {
        const val CONFIDENCE = 0.5f

        /** Obfuscated emulator device paths. */
        val EMULATOR_PATHS: List<String> = ObfuscatedStrings.decodeList(
            "145f5e4d14485458505e4f144a5e564e5f31145f5e4d144a5e564e644b524b5e31145f5e4d14485458505e4f14" +
                "5c5e55425f31145f5e4d14485458505e4f14595a485e595a555f645c5e55425f3114484248144a5e564e644f" +
                "495a585e31144842484f5e5614595255144a5e564e5f",
            0x3B,
        )
    }
}
