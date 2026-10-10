package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.NativeProbe

/**
 * Integritas segmen executable library native: hash diambil saat baseline (pemanggilan
 * pertama) lalu dibandingkan pada pemanggilan berikutnya. Perubahan mengindikasikan
 * library di-patch secara runtime (inline hook / memory patch).
 */
class NativeTextIntegrityCheck(private val native: NativeProbe?) : RaspCheck {

    override val id = "integrity.native_text"
    override val category = Category.INTEGRITY
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val probe = native ?: return CheckResult.Unknown("native probe tidak tersedia")
        return if (probe.isTextModified()) {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "segmen executable library berubah dari baseline"))
            )
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.9f
    }
}
