package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.FileProbe
import io.knightrasp.util.ObfuscatedStrings

/**
 * Presence of the `su` binary in common paths. Medium confidence: the binary may exist on custom ROMs
 * without active root, so it must not be sole evidence.
 */
class SuBinaryCheck(private val files: FileProbe) : RaspCheck {

    override val id = "root.su_binary"
    override val category = Category.ROOT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val found = SU_PATHS.filter(files::exists)
        return if (found.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(found.map { Evidence(id, CONFIDENCE, it) })
        }
    }

    companion object {
        const val CONFIDENCE = 0.6f

        /** Obfuscated: plain paths must not be recoverable from a static string dump. */
        val SU_PATHS: List<String> = ObfuscatedStrings.decodeList(
            "18444e4443525a18555e591844423d18444e4443525a184f555e591844423d1844555e591844423d18444218" +
                "555e591844423d18444e4443525a184453184f555e591844423d18444e4443525a18555e591851565e5b44" +
                "5651521844423d1853564356185b5854565b184f555e591844423d1853564356185b5854565b18555e5918" +
                "44423d1853564356185b5854565b184442",
            0x37,
        )
    }
}
