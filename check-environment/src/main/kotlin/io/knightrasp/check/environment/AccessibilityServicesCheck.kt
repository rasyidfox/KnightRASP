package io.knightrasp.check.environment

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SystemProbe

/**
 * Accessibility services enabled outside the allowlist.
 *
 * Third-party services can read/tap the user's UI (e.g. auto-approve dialogs),
 * but many legitimate users rely on TalkBack and other screen readers.
 * This check therefore:
 * - reports Unknown when `allowedAccessibilityServices` is empty (not configured),
 * - uses low confidence and is meant to be combined with other signals.
 */
class AccessibilityServicesCheck(private val system: SystemProbe) : RaspCheck {

    override val id = "env.accessibility_services"
    override val category = Category.ENVIRONMENT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val allowed = ctx.config.allowedAccessibilityServices.filter { it.isNotBlank() }.toSet()
        if (allowed.isEmpty()) {
            return CheckResult.Unknown("allowedAccessibilityServices not configured")
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
