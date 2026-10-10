package io.knightrasp.telemetry.queue

import io.knightrasp.RASP_SDK_VERSION
import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.telemetry.TelemetrySink
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

data class TelemetryQueueConfig(
    /** Maximum number of stored events; the oldest event is dropped when full. */
    val maxEvents: Int = 100,
    /** Number of events per upload. */
    val batchSize: Int = 10,
    /** Minimum level that is sent; default LOW (NONE is never sent). */
    val minLevel: Level = Level.LOW,
    /** Initial retry delay; doubles on each failure up to [maxRetryDelayMs]. */
    val baseRetryDelayMs: Long = 60_000L,
    val maxRetryDelayMs: Long = 30 * 60_000L,
)

/**
 * A [TelemetrySink] that queues events into [TelemetryQueue] and then uploads them via
 * [TelemetryUploader] in batches on [TelemetryScheduler], with retry backoff.
 *
 * - `report()` only touches the queue (no network) and is called from the main thread.
 * - Upload failures never throw; batches stay stored for another attempt.
 * - [redact] lets the host drop/change fields before they are stored; returning
 *   null means the event is dropped.
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

    /** Drains the queue now, synchronously. Useful for tests and app shutdown. */
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
