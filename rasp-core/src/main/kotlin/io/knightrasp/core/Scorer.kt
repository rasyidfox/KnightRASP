package io.knightrasp.core

import io.knightrasp.config.Thresholds
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment
import kotlin.math.min

/** Hasil dari satu check yang ikut menyumbang skor. */
data class CheckOutcome(
    val checkId: String,
    val category: Category,
    val evidence: List<Evidence>,
)

/**
 * Agregasi evidence menjadi [ThreatAssessment].
 *
 * - Per kategori: noisy-OR — `1 - Π(1 - confidence_i)`.
 * - Global: skor kategori terkuat + bonus kecil bila >= 2 kategori mencurigakan,
 *   sehingga banyak sinyal lemah pada satu kategori tidak otomatis menjadi CRITICAL.
 */
class Scorer(private val thresholds: Thresholds) {

    fun assess(outcomes: List<CheckOutcome>, nowMs: Long): ThreatAssessment {
        val evidence = outcomes.flatMap { it.evidence }
        val byCategory = outcomes
            .filter { it.evidence.isNotEmpty() }
            .groupBy { it.category }
            .mapValues { (_, group) -> noisyOr(group.flatMap { it.evidence }) }

        val strongest = byCategory.values.maxOrNull() ?: 0f
        val bonus = if (byCategory.count { it.value > 0f } >= 2) MULTI_CATEGORY_BONUS else 0f
        val score = min(1f, strongest + bonus)

        return ThreatAssessment(
            score = score,
            level = levelFor(score),
            categories = byCategory,
            evidence = evidence,
            timestampMs = nowMs,
        )
    }

    private fun noisyOr(evidence: List<Evidence>): Float {
        var product = 1f
        for (item in evidence) {
            product *= 1f - item.confidence.coerceIn(0f, 1f)
        }
        return 1f - product
    }

    private fun levelFor(score: Float): Level = when {
        score >= thresholds.high -> Level.CRITICAL
        score >= thresholds.medium -> Level.HIGH
        score >= thresholds.low -> Level.MEDIUM
        score > 0f -> Level.LOW
        else -> Level.NONE
    }

    companion object {
        /** Bonus bila ada >= 2 kategori mencurigakan. */
        const val MULTI_CATEGORY_BONUS = 0.05f
    }
}
