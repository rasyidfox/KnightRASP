package io.knightrasp.telemetry

import io.knightrasp.model.ThreatAssessment

/**
 * Telemetry sink. The default [NOOP] sends no data at all.
 *
 * The delivery implementation (queue, batching, retry) is provided by the optional
 * `rasp-telemetry` module in a later phase; apps are also free to implement it
 * themselves, e.g. forwarding to an internal backend.
 */
fun interface TelemetrySink {
    fun report(assessment: ThreatAssessment)

    companion object {
        @JvmField
        val NOOP: TelemetrySink = TelemetrySink { }
    }
}
