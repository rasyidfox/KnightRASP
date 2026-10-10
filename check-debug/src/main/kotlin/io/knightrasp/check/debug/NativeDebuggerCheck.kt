package io.knightrasp.check.debug

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Debugger detection from the native layer: reads of `TracerPid` and `ptrace(PTRACE_TRACEME)`
 * use raw syscalls, so they do not depend on the easily hooked
 * `Debug.isDebuggerConnected()`.
 */
class NativeDebuggerCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "debug.native_ptrace"
    override val category = Category.DEBUG
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.isDebuggerDetected()) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "tracer detected from the native layer")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.9f
    }
}
