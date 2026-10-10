package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Native library executable segment integrity: a hash is taken at baseline (first
 * call) and compared on subsequent calls. A change indicates the library was
 * patched at runtime (inline hook / memory patch).
 */
class NativeTextIntegrityCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "integrity.native_text"
    override val category = Category.INTEGRITY
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.isTextModified()) {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "library executable segment changed from baseline"))
            )
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.9f
    }
}
