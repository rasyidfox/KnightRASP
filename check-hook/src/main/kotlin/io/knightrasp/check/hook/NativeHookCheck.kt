package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Hook-artifact scanning from the native layer (reads /proc/self/maps via raw
 * syscalls, harder to hook than Java-side reads).
 */
class NativeHookCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "hook.native_maps"
    override val category = Category.HOOK
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.signalB()) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "hook artifacts visible to the native probe")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.85f
    }
}
