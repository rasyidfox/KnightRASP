package io.knightrasp.telemetry.queue

import io.knightrasp.RASP_SDK_VERSION
import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.telemetry.TelemetrySink
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

data class TelemetryQueueConfig(
    /** Jumlah maksimum event tersimpan; event terlama dibuang saat penuh. */
    val maxEvents: Int = 100,
    /** Jumlah event per pengiriman. */
    val batchSize: Int = 10,
    /** Level minimum yang dikirim; default LOW (NONE tidak pernah dikirim). */
    val minLevel: Level = Level.LOW,
    /** Delay awal retry; berlipat dua setiap kegagalan hingga [maxRetryDelayMs]. */
    val baseRetryDelayMs: Long = 60_000L,
    val maxRetryDelayMs: Long = 30 * 60_000L,
)

/**
 * [TelemetrySink] yang mengantre event ke [TelemetryQueue] lalu mengirimnya ke
 * [TelemetryUploader] secara batch di [TelemetryScheduler], dengan retry backoff.
 *
 * - `report()` hanya menyentuh antrean (tanpa jaringan) dan dipanggil dari main thread.
 * - Kegagalan upload tidak pernah melempar; batch tetap tersimpan untuk dicoba lagi.
 * - [redact] dapat dipakai host untuk membuang/mengubah field sebelum disimpan; return
 *   null berarti event dibuang.
 */
class QueuedTelemetrySink(
    private val queue: TelemetryQueue,
    private val uploader: TelemetryUploader,
    private val scheduler: TelemetryScheduler,
    private val config: TelemetryQueueConfig = TelemetryQueueConfig(),
    private val redact: (TelemetryEvent) -> TelemetryEvent? = { it },
) : TelemetrySink {

    private val draining = AtomicBoolean(false)
    private val retryPending = AtomicBoolean(false)
    private var attempt = 0

    override fun report(assessment: ThreatAssessment) {
        if (assessment.level.ordinal < config.minLevel.ordinal) {
            return
        }
        val event = redact(
            TelemetryEvent.from(assessment, RASP_SDK_VERSION, assessment.timestampMs)
        ) ?: return
        runCatching { queue.enqueue(event) }
            .onSuccess { scheduler.execute(::drain) }
    }

    /** Memproses antrean sekarang, sinkron. Berguna untuk test dan shutdown aplikasi. */
    fun flushNow() {
        drain()
    }

    private fun drain() {
        if (!draining.compareAndSet(false, true)) {
            return
        }
        try {
            while (true) {
                val batch = queue.peek(config.batchSize)
                if (batch.isEmpty()) {
                    attempt = 0
                    retryPending.set(false)
                    return
                }
                val uploaded = try {
                    uploader.upload(batch)
                } catch (_: Throwable) {
                    false
                }
                if (!uploaded) {
                    scheduleRetry()
                    return
                }
                queue.removeFirst(batch.size)
                attempt = 0
                retryPending.set(false)
            }
        } finally {
            draining.set(false)
        }
    }

    private fun scheduleRetry() {
        if (!retryPending.compareAndSet(false, true)) {
            return
        }
        val delay = retryDelayMs(attempt)
        attempt++
        scheduler.schedule(delay) {
            retryPending.set(false)
            drain()
        }
    }

    private fun retryDelayMs(attempt: Int): Long {
        val shifted = config.baseRetryDelayMs shl min(attempt, 10)
        return min(shifted, config.maxRetryDelayMs)
    }
}
