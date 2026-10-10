package io.knightrasp.telemetry

import io.knightrasp.model.ThreatAssessment

/**
 * Sink telemetry. Default [NOOP] tidak mengirim data apa pun.
 *
 * Implementasi pengiriman (queue, batching, retry) disediakan modul opsional
 * `rasp-telemetry` pada fase berikutnya; aplikasi juga bebas mengimplementasikan
 * sendiri, mis. meneruskan ke backend internal.
 */
fun interface TelemetrySink {
    fun report(assessment: ThreatAssessment)

    companion object {
        @JvmField
        val NOOP: TelemetrySink = TelemetrySink { }
    }
}
