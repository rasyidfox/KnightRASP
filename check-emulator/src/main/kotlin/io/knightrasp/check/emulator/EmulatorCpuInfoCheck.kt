package io.knightrasp.check.emulator

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.FileProbe
import io.knightrasp.util.TextCodec

/**
 * Emulator markers in `/proc/cpuinfo` (`goldfish`, `ranchu`, `qemu`).
 *
 * Fingerprint/model spoofing only changes `Build.*` values; the kernel's CPU
 * description in `/proc/cpuinfo` is independent, so this catches emulators whose
 * vendor fingerprint looks genuine.
 */
class EmulatorCpuInfoCheck(private val files: FileProbe) : RaspCheck {

    override val id = "emulator.cpuinfo"
    override val category = Category.EMULATOR
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val content = files.read(CPUINFO_PATH)
            ?: return CheckResult.Unknown("cpu info unreadable")

        val lowered = content.lowercase()
        val matches = MARKERS.filter { marker -> marker in lowered }
        return if (matches.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(matches.map { Evidence(id, CONFIDENCE, "marker:$it") })
        }
    }

    companion object {
        const val CONFIDENCE = 0.6f

        /** Obfuscated `/proc/cpuinfo`. */
        private val CPUINFO_PATH: String = TextCodec.decode("045b59444804485b5e42454d44", 0x2B)

        /** Obfuscated emulator CPU markers. */
        val MARKERS: List<String> = TextCodec.decodeList(
            "323a3931333c263d5f27343b363d205f24303820",
            0x55,
        )
    }
}
