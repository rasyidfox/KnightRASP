package io.knightrasp.check.virtualization

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.ProcProbe

/**
 * Nama proses mengandung penanda lingkungan virtual/parallel (mis. `parallel`,
 * `vbox`, `virtual`, `sandbox`) dan berbeda dari nama proses normal aplikasi.
 * Confidence rendah karena penamaan proses internal berbeda-beda antar produk.
 */
class SuspiciousProcessNameCheck(private val proc: ProcProbe) : RaspCheck {

    override val id = "virtualization.process_name"
    override val category = Category.VIRTUALIZATION
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val raw = proc.selfCmdline()
            ?: return CheckResult.Unknown("tidak bisa membaca /proc/self/cmdline")
        val processName = raw.trim()
        if (processName.isEmpty()) {
            return CheckResult.Unknown("nama proses kosong")
        }
        val lowered = processName.lowercase()
        val matched = MARKERS.firstOrNull { it in lowered }
        return if (matched != null && processName != ctx.packageName) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "proses:$processName")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.3f

        val MARKERS = listOf("parallel", "vbox", "virtual", "cloner", "sandbox")
    }
}
