package io.knightrasp.core

import io.knightrasp.config.Environment
import io.knightrasp.config.RaspConfig
import io.knightrasp.config.RaspRules
import io.knightrasp.config.Thresholds
import io.knightrasp.model.Evidence
import kotlin.math.min

/**
 * Menerapkan [RaspRules] ke pipeline deteksi:
 * - memfilter check yang dimatikan,
 * - menyesuaikan confidence evidence per `checkId`,
 * - mengganti ambang threshold.
 *
 * Rules yang kedaluwarsa diabaikan seluruhnya. Pada [Environment.QA], check yang wajar
 * menyala saat development (debugger, ADB, developer options) dimatikan otomatis.
 */
object RuleTuner {

    /** Check yang dimatikan otomatis pada `Environment.QA`. */
    val QA_DISABLED_CHECKS = setOf(
        "env.adb_enabled",
        "env.developer_options",
        "debug.debugger_connected",
        "debug.tracer_pid",
        "debug.native_ptrace",
    )

    fun activeRules(config: RaspConfig, nowMs: Long): RaspRules? =
        config.rules?.takeIf { !it.isExpired(nowMs) }

    fun effectiveThresholds(config: RaspConfig, rules: RaspRules?): Thresholds =
        rules?.thresholds ?: config.thresholds

    fun disabledChecks(config: RaspConfig, rules: RaspRules?): Set<String> {
        val qa = if (config.environment == Environment.QA) QA_DISABLED_CHECKS else emptySet()
        return config.disabledChecks + qa + rules?.disabledChecks.orEmpty()
    }

    fun evidenceTuner(rules: RaspRules?): (checkId: String, evidence: List<Evidence>) -> List<Evidence> {
        val scales = rules?.confidenceScale.orEmpty()
        if (scales.isEmpty()) {
            return { _, evidence -> evidence }
        }
        return { checkId, evidence ->
            val scale = scales[checkId] ?: 1f
            if (scale == 1f) {
                evidence
            } else {
                evidence.map { item ->
                    item.copy(confidence = min(1f, item.confidence * scale).coerceAtLeast(0f))
                }
            }
        }
    }
}
