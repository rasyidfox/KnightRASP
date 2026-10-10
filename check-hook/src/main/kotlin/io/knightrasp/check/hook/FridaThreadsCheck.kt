package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.ProcProbe
import io.knightrasp.util.ObfuscatedStrings

/**
 * Frida-specific thread names (`gmain`, `gdbus`, `gum-js-loop`, `pool-frida`) appear in
 * the process thread list. These names practically never appear in normal apps, so
 * detection is high confidence.
 */
class FridaThreadsCheck(private val proc: ProcProbe) : RaspCheck {

    override val id = "hook.frida_threads"
    override val category = Category.HOOK
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val threads = proc.threadNames()
        if (threads.isEmpty()) {
            return CheckResult.Unknown("thread list unreadable")
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

        /** Obfuscated Frida thread-name markers. */
        val MARKERS: List<String> = ObfuscatedStrings.decodeList(
            "040e020a0d6904070116106904160e4e09104e0f0c0c1369130c0c0f4e05110a07026905110a0702",
            0x63,
        )
    }
}
