package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.FileProbe

/**
 * Keberadaan binary `su` di path umum. Keyakinan sedang: binary bisa ada di custom ROM
 * tanpa root aktif, sehingga tidak boleh menjadi bukti tunggal.
 */
class SuBinaryCheck(private val files: FileProbe) : RaspCheck {

    override val id = "root.su_binary"
    override val category = Category.ROOT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val found = SU_PATHS.filter(files::exists)
        return if (found.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(found.map { Evidence(id, CONFIDENCE, it) })
        }
    }

    companion object {
        const val CONFIDENCE = 0.6f

        val SU_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
        )
    }
}
