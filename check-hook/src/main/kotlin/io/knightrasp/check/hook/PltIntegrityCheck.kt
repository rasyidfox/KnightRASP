package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * PLT/GOT integrity: watched entries (e.g. `__system_property_get`, `dlsym`)
 * are compared against the addresses `dlsym` resolves. A PLT-hooked function —
 * for example one rewritten to fake the boot state — shows up as a mismatch.
 */
class PltIntegrityCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "hook.plt_integrity"
    override val category = Category.HOOK
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.signalH()) {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "PLT/GOT entry redirected after load"))
            )
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.6f
    }
}
