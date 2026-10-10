package io.knightrasp.config

/**
 * Tuning coming from remote rules (their signature has been verified by the
 * `rasp-rules` module). Rules are data-only: no free-form code/expressions are executed.
 *
 * When rules are expired, the runtime ignores them and falls back to the static [RaspConfig].
 *
 * @param version rules version; increase monotonically when publishing an update.
 * @param issuedAtMs issue time (epoch ms) for auditing.
 * @param expiresAtMs validity limit; null means no expiry.
 * @param disabledChecks checks disabled on the client side (takes precedence over enabledChecks).
 * @param confidenceScale confidence multiplier per `checkId`, e.g. `0.5` to lower
 *   the confidence of checks that often false-positive in the field; `0.0` effectively disables.
 * @param thresholds level threshold override; null means use the config thresholds.
 * @param signatureVerified true when these rules passed signature verification.
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
