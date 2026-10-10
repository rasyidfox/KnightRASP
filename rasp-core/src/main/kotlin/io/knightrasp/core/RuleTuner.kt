package io.knightrasp.core

import io.knightrasp.config.Environment
import io.knightrasp.config.RaspConfig
import io.knightrasp.config.RaspRules
import io.knightrasp.config.Thresholds
import io.knightrasp.model.Evidence
import kotlin.math.min

/**
 * Applies [RaspRules] to the detection pipeline:
 * - filters out disabled checks,
 * - adjusts evidence confidence per `checkId`,
 * - replaces the score thresholds.
 *
 * Expired rules are ignored entirely. In [Environment.QA], checks that normally
 * fire during development (debugger, ADB, developer options) are disabled automatically.
 */
object RuleTuner {

    /** Checks disabled automatically in `Environment.QA`. */
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
