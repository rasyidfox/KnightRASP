package io.knightrasp

import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment

/**
 * Callback hasil scan dan error SDK.
 *
 * Semua callback dipanggil di main thread. Satu listener yang melempar exception
 * tidak menghentikan listener lain.
 */
interface RaspListener {
    /** Dipanggil setiap selesai scan asinkron. */
    fun onAssessment(result: ThreatAssessment) {}

    /** Dipanggil saat SDK mengalami error internal (fail-open). */
    fun onError(error: RaspError) {}
}
