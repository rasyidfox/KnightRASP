package io.knightrasp.check.environment

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SettingsProbe
import io.knightrasp.util.ObfuscatedStrings

/**
 * Mock location enabled (`Settings.Secure`). On modern Android this flag maps directly
 * to an allowed mock app; medium confidence because it may be enabled for legitimate
 * testing.
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

        /** Obfuscated Settings.Secure key. */
        val KEY_MOCK_LOCATION: String =
            ObfuscatedStrings.decode("74767a724675767a786d707677", 0x19)

        private const val ENABLED = 1
        private const val DEFAULT = 0
    }
}
