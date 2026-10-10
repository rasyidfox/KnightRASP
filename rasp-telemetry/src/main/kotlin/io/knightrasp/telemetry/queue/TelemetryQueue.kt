package io.knightrasp.telemetry.queue

/**
 * Antrean telemetry persisten dengan batas jumlah event.
 *
 * Saat antrean penuh, event **terlama** dibuang agar insiden terbaru tetap terkirim.
 * Semua operasi disinkronkan; store dianggap sebagai satu-satunya sumber kebenaran.
 */
class TelemetryQueue(
    private val store: TelemetryStore,
    private val maxEvents: Int = 100,
    private val codec: TelemetryEventCodec = TelemetryEventCodec(),
) {
    private val lock = Any()

    fun enqueue(event: TelemetryEvent) = synchronized(lock) {
        val lines = store.load().toMutableList()
        lines += codec.encode(event)
        while (lines.size > maxEvents) {
            lines.removeAt(0)
        }
        store.replaceAll(lines)
    }

    fun peek(max: Int): List<TelemetryEvent> = synchronized(lock) {
        store.load().take(max).mapNotNull(codec::decode)
    }

    fun removeFirst(count: Int) = synchronized(lock) {
        if (count <= 0) {
            return@synchronized
        }
        store.replaceAll(store.load().drop(count))
    }

    fun size(): Int = synchronized(lock) { store.load().size }

    fun clear() = synchronized(lock) { store.replaceAll(emptyList()) }
}
