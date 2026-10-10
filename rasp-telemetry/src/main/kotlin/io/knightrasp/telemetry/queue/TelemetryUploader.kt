package io.knightrasp.telemetry.queue

/** Tujuan pengiriman batch telemetry; biasanya backend aplikasi host. */
fun interface TelemetryUploader {
    /**
     * Kirim satu batch. Kembalikan `true` bila batch diterima (boleh dihapus dari
     * antrean); `false` atau exception berarti akan dicoba ulang dengan backoff.
     */
    fun upload(events: List<TelemetryEvent>): Boolean
}
