package io.knightrasp.config

/**
 * Tuning yang berasal dari remote rules (sudah diverifikasi tanda tangannya oleh modul
 * `rasp-rules`). Rules bersifat data-only: tidak ada kode/ekspresi bebas yang dieksekusi.
 *
 * Bila rules kedaluwarsa, runtime mengabaikannya dan kembali ke [RaspConfig] statis.
 *
 * @param version versi rules; naikkan monoton saat menerbitkan update.
 * @param issuedAtMs waktu terbit (epoch ms) untuk audit.
 * @param expiresAtMs batas berlaku; null berarti tanpa kedaluwarsa.
 * @param disabledChecks check yang dimatikan di sisi klien (menang atas enabledChecks).
 * @param confidenceScale pengali confidence per `checkId`, mis. `0.5` untuk menurunkan
 *   keyakinan check yang sering false positive di lapangan; `0.0` efektif mematikan.
 * @param thresholds override ambang level; null berarti memakai ambang config.
 * @param signatureVerified true bila rules ini lolos verifikasi tanda tangan.
 */
data class RaspRules(
    val version: Int,
    val issuedAtMs: Long = 0L,
    val expiresAtMs: Long? = null,
    val disabledChecks: Set<String> = emptySet(),
    val confidenceScale: Map<String, Float> = emptyMap(),
    val thresholds: Thresholds? = null,
    val signatureVerified: Boolean = false,
) {
    fun isExpired(nowMs: Long): Boolean = expiresAtMs?.let { nowMs > it } ?: false
}
