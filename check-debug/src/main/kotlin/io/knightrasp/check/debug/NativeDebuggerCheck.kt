package io.knightrasp.check.debug

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Deteksi debugger dari layer native: pembacaan `TracerPid` dan `ptrace(PTRACE_TRACEME)`
 * memakai syscall langsung, sehingga tidak bergantung pada `Debug.isDebuggerConnected()`
 * yang mudah di-hook.
 */
class NativeDebuggerCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "debug.native_ptrace"
    override val category = Category.DEBUG
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe tidak tersedia")
        return if (probe.isDebuggerDetected()) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "tracer terdeteksi dari layer native")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.9f
    }
}
