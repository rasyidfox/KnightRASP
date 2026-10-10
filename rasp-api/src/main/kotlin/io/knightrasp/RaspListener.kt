package io.knightrasp

import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment

/**
 * Callbacks for scan results and SDK errors.
 *
 * All callbacks are invoked on the main thread. One listener throwing an exception
 * does not stop the other listeners.
 */
interface RaspListener {
    /** Called whenever an asynchronous scan completes. */
    fun onAssessment(result: ThreatAssessment) {}

    /** Called when the SDK hits an internal error (fail-open). */
    fun onError(error: RaspError) {}
}
