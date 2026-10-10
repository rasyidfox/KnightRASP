package io.knightrasp.check.debug

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SystemProbe

/** Debugger connected (JDWP). High confidence: it almost always means instrumentation is active. */
class DebuggerFlagCheck(private val system: SystemProbe) : RaspCheck {

    override val id = "debug.debugger_connected"
    override val category = Category.DEBUG
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        return if (system.isDebuggerConnected()) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "Debug.isDebuggerConnected() == true")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.9f
    }
}
