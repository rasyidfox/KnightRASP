package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Memory-map shapes typical of injected instrumentation agents: `memfd:`-backed
 * mappings (excluding ART's `jit-cache`) and writable+executable `.so` mappings.
 *
 * Renaming `frida-server`/gadget does not change how the agent maps its memory, so
 * this complements `hook.maps_artifacts` (which searches for known names).
 */
class InjectedMemoryCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "hook.injected_memory"
    override val category = Category.HOOK
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.signalF()) {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "memory map shows an injected agent shape"))
            )
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.6f
    }
}
