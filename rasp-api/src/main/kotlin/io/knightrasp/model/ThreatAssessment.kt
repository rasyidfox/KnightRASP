package io.knightrasp.model

/**
 * Hasil agregasi satu atau beberapa scan.
 *
 * @param score skor keyakinan global 0..1 (agregasi antar kategori).
 * @param level pemetaan [score] terhadap ambang; NONE berarti tidak ada indikasi.
 * @param categories skor per kategori (noisy-OR evidence di kategori yang sama).
 * @param evidence seluruh evidence yang terkumpul.
 * @param timestampMs waktu assessment dibuat (epoch ms).
 */
data class ThreatAssessment(
    val score: Float,
    val level: Level,
    val categories: Map<Category, Float>,
    val evidence: List<Evidence>,
    val timestampMs: Long,
) {
    companion object {
        /** Assessment kosong; dipakai saat scan tidak dapat dijalankan. */
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
