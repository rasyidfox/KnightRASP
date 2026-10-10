package io.knightrasp.check.virtualization

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.ProcProbe
import io.knightrasp.util.TextCodec

/**
 * Process name contains virtual/parallel environment markers (e.g. `parallel`,
 * `vbox`, `virtual`, `sandbox`) and differs from the app's normal process name.
 * Low confidence because internal process naming varies between products.
 */
class SuspiciousProcessNameCheck(private val proc: ProcProbe) : RaspCheck {

    override val id = "virtualization.process_name"
    override val category = Category.VIRTUALIZATION
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val raw = proc.selfCmdline()
            ?: return CheckResult.Unknown("process name unreadable")
        val processName = raw.trim()
        if (processName.isEmpty()) {
            return CheckResult.Unknown("empty process name")
        }
        val lowered = processName.lowercase()
        val matched = MARKERS.firstOrNull { it in lowered }
        return if (matched != null && processName != ctx.packageName) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "process:$processName")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.3f

        /** Obfuscated virtual/parallel environment process markers. */
        val MARKERS: List<String> = TextCodec.decodeList(
            "5f4e5d4e43434a4325594d40572559465d5b5a4e43254c4340414a5d255c4e414b4d4057",
            0x2F,
        )
    }
}
