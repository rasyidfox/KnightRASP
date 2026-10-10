package io.knightrasp.check.environment

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SettingsProbe

/** Developer options aktif. Sinyal lemah; biasanya hanya relevan bila digabung sinyal lain. */
class DeveloperOptionsCheck(private val settings: SettingsProbe) : RaspCheck {

    override val id = "env.developer_options"
    override val category = Category.ENVIRONMENT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        return if (settings.globalInt(KEY_DEVELOPMENT_SETTINGS_ENABLED, DEFAULT) == ENABLED) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "development settings enabled")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.3f
        const val KEY_DEVELOPMENT_SETTINGS_ENABLED = "development_settings_enabled"
        private const val ENABLED = 1
        private const val DEFAULT = 0
    }
}
