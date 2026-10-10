package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Native library executable-segment integrity.
 *
 * Two layers: a load-time baseline (detects post-load patching/inline hooks) and
 * a build-time pinned FNV-1a digest of the executable segment (detects patches
 * applied before the library is loaded — Frida gadget/spawn, repackaged `.so`).
 * The pinned slot (`.krpin`) is filled by `pin_digest.py` as a CMake POST_BUILD
 * step; when Python is unavailable at build time the pin stays zero and only the
 * baseline layer is active.
 */
class NativeTextIntegrityCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "integrity.native_text"
    override val category = Category.INTEGRITY
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.signalC()) {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "library executable segment does not match its pinned digest"))
            )
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.9f
    }
}
