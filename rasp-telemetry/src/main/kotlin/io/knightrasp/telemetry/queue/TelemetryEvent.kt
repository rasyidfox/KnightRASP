package io.knightrasp.telemetry.queue

import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment
import java.util.UUID

/**
 * Snapshot event sent to the backend.
 *
 * There are no device identifiers (IMEI, ANDROID_ID, etc.) here; adding them
 * is the host app's decision and its responsibility under privacy
 * policies (e.g. Play Data Safety / local data-protection laws).
 */
data class TelemetryEvent(
    val id: String,
    val timestampMs: Long,
    val level: Level,
    val score: Float,
    val categories: Map<Category, Float>,
    val evidence: List<Evidence>,
    val sdkVersion: String,
) {
    companion object {
        @JvmStatic
        fun from(assessment: ThreatAssessment, sdkVersion: String, nowMs: Long): TelemetryEvent =
            TelemetryEvent(
                id = UUID.randomUUID().toString(),
                timestampMs = if (assessment.timestampMs > 0L) assessment.timestampMs else nowMs,
                level = assessment.level,
                score = assessment.score,
                categories = assessment.categories,
                evidence = assessment.evidence,
                sdkVersion = sdkVersion,
            )
    }
}
