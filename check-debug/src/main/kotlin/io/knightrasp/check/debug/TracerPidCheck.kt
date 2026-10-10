package io.knightrasp.check.debug

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.ProcProbe

/**
 * `TracerPid` pada `/proc/self/status` bukan nol berarti proses sedang di-ptrace
 * (debugger native, frida, atau tracer lain).
 */
class TracerPidCheck(private val proc: ProcProbe) : RaspCheck {

    override val id = "debug.tracer_pid"
    override val category = Category.DEBUG
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val status = proc.selfStatus()
            ?: return CheckResult.Unknown("tidak bisa membaca /proc/self/status")
        val tracerPid = TRACER_PID_PATTERN.find(status)?.groupValues?.getOrNull(1)?.toIntOrNull()
            ?: return CheckResult.Unknown("TracerPid tidak ditemukan di /proc/self/status")

        return if (tracerPid > 0) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "TracerPid=$tracerPid")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.9f

        private val TRACER_PID_PATTERN = Regex("""TracerPid:\s*(\d+)""")
    }
}
