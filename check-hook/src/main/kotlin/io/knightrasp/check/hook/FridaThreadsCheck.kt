package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.ProcProbe

/**
 * Nama thread khas Frida (`gmain`, `gdbus`, `gum-js-loop`, `pool-frida`) terlihat pada
 * daftar thread proses. Nama-nama ini praktis tidak muncul di aplikasi normal, sehingga
 * keyakinan tinggi bila ditemukan.
 */
class FridaThreadsCheck(private val proc: ProcProbe) : RaspCheck {

    override val id = "hook.frida_threads"
    override val category = Category.HOOK
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val threads = proc.threadNames()
        if (threads.isEmpty()) {
            return CheckResult.Unknown("daftar thread tidak terbaca")
        }
        val matches = threads.filter { name ->
            MARKERS.any { marker -> name.contains(marker, ignoreCase = true) }
        }
        return if (matches.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(matches.map { Evidence(id, CONFIDENCE, "thread:$it") })
        }
    }

    companion object {
        const val CONFIDENCE = 0.8f

        val MARKERS = listOf("gmain", "gdbus", "gum-js-loop", "pool-frida", "frida")
    }
}
