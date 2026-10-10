package io.knightrasp.check.environment

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SystemProbe

/**
 * Layanan accessibility yang aktif di luar allowlist.
 *
 * Layanan pihak ketiga bisa membaca/menekan UI pengguna (mis. menyetujui dialog secara
 * otomatis), tetapi banyak pengguna sah memakai TalkBack dan pembaca layar lain.
 * Karena itu check ini:
 * - melaporkan Unknown bila `allowedAccessibilityServices` kosong (belum dikonfigurasi),
 * - memakai confidence rendah dan diharapkan digabung sinyal lain.
 */
class AccessibilityServicesCheck(private val system: SystemProbe) : RaspCheck {

    override val id = "env.accessibility_services"
    override val category = Category.ENVIRONMENT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val allowed = ctx.config.allowedAccessibilityServices.filter { it.isNotBlank() }.toSet()
        if (allowed.isEmpty()) {
            return CheckResult.Unknown("allowedAccessibilityServices belum dikonfigurasi")
        }
        val enabled = system.enabledAccessibilityServiceIds()
        if (enabled.isEmpty()) {
            return CheckResult.Clean
        }
        val unknown = enabled.filter { it !in allowed }
        return if (unknown.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(unknown.map { Evidence(id, CONFIDENCE, it) })
        }
    }

    companion object {
        const val CONFIDENCE = 0.4f
    }
}
