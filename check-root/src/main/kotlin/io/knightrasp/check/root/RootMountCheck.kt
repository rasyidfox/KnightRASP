package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Root-framework artifacts visible in the process mount namespace
 * (`magisk`, `kernelsu`, `ksud`, `debug_ramdisk`).
 *
 * Read natively with a raw syscall; complements `root.su_binary` for cases where
 * Magisk's deny-list hides binaries and `/data/adb` is not readable by the app.
 */
class RootMountCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "root.native_mounts"
    override val category = Category.ROOT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.signalD()) {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "root mounts visible in the mount namespace"))
            )
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.5f
    }
}
