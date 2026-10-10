package io.knightrasp.config

import io.knightrasp.model.ThreatAssessment

/**
 * Hooks for app-level actions the SDK cannot perform alone.
 *
 * Implementations are called on the main thread by the response executor. In [Mode.MONITOR]
 * all actions here are skipped, so the SDK is safe to ship to production to measure
 * false positives first.
 */
interface HostActions {
    /** Temporarily disables sensitive features (e.g. large transfers, biometrics). */
    fun degrade(assessment: ThreatAssessment) {}

    /** Clears tokens/session and forces the user to log in again. */
    fun logout(assessment: ThreatAssessment) {}

    /** Blocks the next sensitive operations until review. */
    fun blockSensitiveOps(assessment: ThreatAssessment) {}

    companion object {
        /** Empty implementation for apps that have not prepared follow-up actions yet. */
        @JvmField
        val NONE: HostActions = object : HostActions {}
    }
}
