package io.knightrasp.telemetry.queue

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/** Scheduling abstraction so [QueuedTelemetrySink] is deterministic in unit tests. */
interface TelemetryScheduler {
    fun execute(task: () -> Unit)

    fun schedule(delayMs: Long, task: () -> Unit)
}

/** Production implementation: a single daemon thread. */
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
