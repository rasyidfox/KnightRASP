package io.knightrasp.model

/**
 * A single signal detected by a check.
 *
 * @param ruleId id of the check that produced the signal, e.g. `root.su_binary`.
 * @param confidence certainty 0..1 that this signal is genuine.
 * @param detail additional information (path, package name, etc.) — must not contain PII.
 */
data class Evidence(
    val ruleId: String,
    val confidence: Float,
    val detail: String? = null,
)
