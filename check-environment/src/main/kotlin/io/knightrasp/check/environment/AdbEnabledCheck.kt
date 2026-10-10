package io.knightrasp.check.environment

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SettingsProbe

/** ADB aktif pada perangkat. Keyakinan sedang: mempermudah instrumentasi eksternal. */
class AdbEnabledCheck(private val settings: SettingsProbe) : RaspCheck {

    override val id = "env.adb_enabled"
    override val category = Category.ENVIRONMENT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        return if (settings.globalInt(KEY_ADB_ENABLED, DEFAULT) == ENABLED) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "adb enabled")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.4f
        const val KEY_ADB_ENABLED = "adb_enabled"
        private const val ENABLED = 1
        private const val DEFAULT = 0
    }
}
