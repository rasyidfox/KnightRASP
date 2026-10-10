package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Compares the executable segments of watched system libraries (`libart.so`,
 * `libc.so`, `libandroid_runtime.so`) against the files on disk.
 *
 * ART-level hook frameworks (LSPosed, SandHook, Epic, ...) patch functions inside
 * those libraries without touching our own code, and hiding their library names
 * does not help: the bytes on disk are kept pristine by verified boot.
 */
class SystemLibraryIntegrityCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "hook.system_libraries"
    override val category = Category.HOOK
    override val cost = Cost.MEDIUM

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.signalG()) {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "system library executable segment differs from disk"))
            )
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.7f
    }
}
