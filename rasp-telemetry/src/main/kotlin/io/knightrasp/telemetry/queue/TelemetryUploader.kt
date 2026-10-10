package io.knightrasp.telemetry.queue

/** Destination for telemetry batch uploads; usually the host app's backend. */
fun interface TelemetryUploader {
    /**
     * Uploads one batch. Returns `true` when the batch is accepted (it may be removed from
     * the queue); `false` or an exception means it will be retried with backoff.
     */
    fun upload(events: List<TelemetryEvent>): Boolean
}
