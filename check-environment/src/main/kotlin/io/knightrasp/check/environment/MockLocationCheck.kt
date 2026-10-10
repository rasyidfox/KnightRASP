package io.knightrasp.check.environment

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SettingsProbe

/**
 * Mock location aktif (`Settings.Secure`). Pada Android modern flag ini terkait langsung
 * dengan aplikasi mock yang diizinkan; confidence sedang karena bisa aktif untuk testing
 * yang sah.
 */
class MockLocationCheck(private val settings: SettingsProbe) : RaspCheck {

    override val id = "env.mock_location"
    override val category = Category.ENVIRONMENT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        return if (settings.secureInt(KEY_MOCK_LOCATION, DEFAULT) == ENABLED) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "mock location enabled")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.5f
        const val KEY_MOCK_LOCATION = "mock_location"
        private const val ENABLED = 1
        private const val DEFAULT = 0
    }
}
