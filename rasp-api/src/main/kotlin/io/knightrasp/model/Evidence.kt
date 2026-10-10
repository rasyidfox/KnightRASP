package io.knightrasp.model

/**
 * Satu sinyal terdeteksi dari sebuah check.
 *
 * @param ruleId id check yang menghasilkan sinyal, mis. `root.su_binary`.
 * @param confidence keyakinan 0..1 bahwa sinyal ini benar.
 * @param detail keterangan tambahan (path, nama paket, dsb.) — jangan berisi PII.
 */
data class Evidence(
    val ruleId: String,
    val confidence: Float,
    val detail: String? = null,
)
