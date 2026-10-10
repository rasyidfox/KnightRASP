package io.knightrasp.model

/**
 * Result of aggregating one or more scans.
 *
 * @param score global confidence score 0..1 (aggregated across categories).
 * @param level mapping of [score] to thresholds; NONE means no indication.
 * @param categories per-category scores (noisy-OR of evidence in the same category).
 * @param evidence all collected evidence.
 * @param timestampMs time the assessment was created (epoch ms).
 */
data class ThreatAssessment(
    val score: Float,
    val level: Level,
    val categories: Map<Category, Float>,
    val evidence: List<Evidence>,
    val timestampMs: Long,
) {
    companion object {
        /** Empty assessment; used when a scan cannot run. */
        @JvmStatic
        fun unknown(nowMs: Long): ThreatAssessment =
            ThreatAssessment(
                score = 0f,
                level = Level.NONE,
                categories = emptyMap(),
                evidence = emptyList(),
                timestampMs = nowMs,
            )
    }
}

enum class Level { NONE, LOW, MEDIUM, HIGH, CRITICAL }
