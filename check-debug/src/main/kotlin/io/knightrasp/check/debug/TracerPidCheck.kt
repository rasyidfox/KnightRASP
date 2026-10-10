package io.knightrasp.check.debug

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.ProcProbe
import io.knightrasp.util.ObfuscatedStrings

/**
 * A non-zero `TracerPid` in `/proc/self/status` means the process is being ptraced
 * (native debugger, frida, or another tracer).
 */
class TracerPidCheck(private val proc: ProcProbe) : RaspCheck {

    override val id = "debug.tracer_pid"
    override val category = Category.DEBUG
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val status = proc.selfStatus()
            ?: return CheckResult.Unknown("status unreadable")
        val tracerPid = TRACER_PID_PATTERN.find(status)?.groupValues?.getOrNull(1)?.toIntOrNull()
            ?: return CheckResult.Unknown("unexpected status format")

        return if (tracerPid > 0) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "pid=$tracerPid")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.9f

        /** Obfuscated regex `TracerPid:\s*(\d+)`. */
        private val TRACER_PID_PATTERN: Regex =
            Regex(ObfuscatedStrings.decode("193f2c2e283f1d242977113e676511296664", 0x4D))
    }
}
