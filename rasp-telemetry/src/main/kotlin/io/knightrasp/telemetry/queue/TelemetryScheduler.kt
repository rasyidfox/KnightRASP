package io.knightrasp.telemetry.queue

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/** Abstraksi penjadwalan agar [QueuedTelemetrySink] deterministik di unit test. */
interface TelemetryScheduler {
    fun execute(task: () -> Unit)

    fun schedule(delayMs: Long, task: () -> Unit)
}

/** Implementasi produksi: satu thread daemon. */
class ExecutorTelemetryScheduler(
    private val executor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "knightrasp-telemetry").apply { isDaemon = true }
    },
) : TelemetryScheduler, AutoCloseable {

    override fun execute(task: () -> Unit) {
        executor.execute(task)
    }

    override fun schedule(delayMs: Long, task: () -> Unit) {
        executor.schedule(task, delayMs, TimeUnit.MILLISECONDS)
    }

    override fun close() {
        executor.shutdown()
    }
}
