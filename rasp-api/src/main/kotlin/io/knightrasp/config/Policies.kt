package io.knightrasp.config

import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment

/** Ready-to-use policy presets. */
object Policies {

    /**
     * "Silent" policy: as soon as the threat level reaches [threshold], the app is
     * force-closed with no log, dialog, or error of any kind (the process exits via the native
     * `exit_group` syscall when the native library is available).
     *
     * Only effective in [Mode.PROTECT]; in [Mode.MONITOR] the `Exit` response is skipped
     * by the executor.
     *
     * Example: `RaspConfig(mode = Mode.PROTECT, policy = Policies.silentKillOn(Level.HIGH))`
     */
    @JvmStatic
    fun silentKillOn(threshold: Level): Policy = Policy { assessment: ThreatAssessment ->
        if (assessment.level >= threshold) listOf(Response.Exit) else emptyList()
    }

    /**
     * Like [silentKillOn], but sends the assessment to [TelemetrySink] first
     * (useful when the host wants to record the incident before the process exits).
     */
    @JvmStatic
    fun reportThenSilentKillOn(threshold: Level): Policy = Policy { assessment ->
        if (assessment.level >= threshold) listOf(Response.Report, Response.Exit) else emptyList()
    }
}
