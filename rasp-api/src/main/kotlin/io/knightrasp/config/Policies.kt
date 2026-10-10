package io.knightrasp.config

import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment

/** Preset policy siap pakai. */
object Policies {

    /**
     * Kebijakan "senyap": begitu level ancaman mencapai [threshold], aplikasi ditutup
     * paksa tanpa log, dialog, atau error apa pun (proses berhenti lewat syscall native
     * `exit_group` bila library native tersedia).
     *
     * Hanya efektif pada [Mode.PROTECT]; pada [Mode.MONITOR] response `Exit` dilewati
     * oleh executor.
     *
     * Contoh: `RaspConfig(mode = Mode.PROTECT, policy = Policies.silentKillOn(Level.HIGH))`
     */
    @JvmStatic
    fun silentKillOn(threshold: Level): Policy = Policy { assessment: ThreatAssessment ->
        if (assessment.level >= threshold) listOf(Response.Exit) else emptyList()
    }

    /**
     * Seperti [silentKillOn], tapi mengirim assessment ke [TelemetrySink] terlebih
     * dahulu (berguna bila host ingin mencatat insiden sebelum proses berhenti).
     */
    @JvmStatic
    fun reportThenSilentKillOn(threshold: Level): Policy = Policy { assessment ->
        if (assessment.level >= threshold) listOf(Response.Report, Response.Exit) else emptyList()
    }
}
