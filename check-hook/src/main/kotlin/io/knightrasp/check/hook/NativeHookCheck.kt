package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Pemindaian artefak hook dari layer native (pembacaan /proc/self/maps memakai syscall
 * langsung, lebih sulit di-hook daripada pembacaan lewat Java).
 */
class NativeHookCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "hook.native_maps"
    override val category = Category.HOOK
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe tidak tersedia")
        return if (probe.isHooked()) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "artefak hook terlihat oleh native probe")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.85f
    }
}
