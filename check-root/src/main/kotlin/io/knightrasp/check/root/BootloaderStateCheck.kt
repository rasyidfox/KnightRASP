package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Verified-boot / bootloader state (`ro.boot.verifiedbootstate` orange/yellow,
 * `ro.boot.flash.locked=0`, or `ro.boot.vbmeta.device_state=unlocked`).
 *
 * Unlike binaries or `/data/adb`, this state comes from the bootloader and cannot
 * be hidden by Magisk's deny-list. An unlocked bootloader is not root by itself,
 * but it is a strong "modified device" signal and a common prerequisite for it.
 */
class BootloaderStateCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "root.bootloader_state"
    override val category = Category.ROOT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe unavailable")
        return if (probe.signalE()) {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "verified-boot state indicates a modified boot image"))
            )
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.5f
    }
}
