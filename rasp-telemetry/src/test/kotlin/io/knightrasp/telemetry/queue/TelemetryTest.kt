package io.knightrasp.telemetry.queue

import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TelemetryEventCodecTest {

    private val codec = TelemetryEventCodec()

    @Test
    fun roundtrip_preserves_fields() {
        val event = TelemetryEvent(
            id = "id-1",
            timestampMs = 1234L,
            level = Level.HIGH,
            score = 0.77f,
            categories = mapOf(Category.ROOT to 0.7f, Category.HOOK to 0.2f),
            evidence = listOf(
                Evidence("root.su_binary", 0.6f, "/system/xbin/su"),
                Evidence("hook.frida_threads", 0.8f, null),
            ),
            sdkVersion = "0.1.0",
        )

        val decoded = codec.decode(codec.encode(event))

        assertEquals(event, decoded)
    }

    @Test
    fun garbage_decodes_to_null() {
        assertEquals(null, codec.decode("not json"))
    }

    @Test
    fun unknown_category_is_skipped() {
        val line = """{"id":"x","ts":1,"level":"LOW","score":0.4,"sdk":"0.1.0",""" +
            """"categories":{"NOT_PRESENT":0.9,"ROOT":0.5},"evidence":[]}"""

        val decoded = codec.decode(line)

        assertNotNull(decoded)
        assertEquals(mapOf(Category.ROOT to 0.5f), decoded!!.categories)
    }
}

class TelemetryQueueTest {

    private fun event(id: String) = TelemetryEvent(
        id = id,
        timestampMs = 1L,
        level = Level.HIGH,
        score = 0.9f,
        categories = emptyMap(),
        evidence = emptyList(),
        sdkVersion = "0.1.0",
    )

    @Test
    fun drops_oldest_when_full() {
        val queue = TelemetryQueue(InMemoryStore(), maxEvents = 2)

        queue.enqueue(event("a"))
        queue.enqueue(event("b"))
        queue.enqueue(event("c"))

        assertEquals(2, queue.size())
        assertEquals(listOf("b", "c"), queue.peek(10).map { it.id })
    }

    @Test
    fun peek_limits_and_remove_first_acknowledges() {
        val queue = TelemetryQueue(InMemoryStore(), maxEvents = 10)
        queue.enqueue(event("a"))
        queue.enqueue(event("b"))
        queue.enqueue(event("c"))

        assertEquals(listOf("a", "b"), queue.peek(2).map { it.id })
        queue.removeFirst(2)

        assertEquals(listOf("c"), queue.peek(10).map { it.id })
    }

    @Test
    fun clear_empties_queue() {
        val queue = TelemetryQueue(InMemoryStore(), maxEvents = 10)
        queue.enqueue(event("a"))

        queue.clear()

        assertEquals(0, queue.size())
    }
}

class QueuedTelemetrySinkTest {

    private class CollectingUploader(
        var failTimes: Int = 0,
    ) : TelemetryUploader {
        val batches = mutableListOf<List<TelemetryEvent>>()

        override fun upload(events: List<TelemetryEvent>): Boolean {
            if (failTimes > 0) {
                failTimes--
                return false
            }
            batches += events
            return true
        }
    }

    private fun assessment(level: Level = Level.HIGH, timestampMs: Long = 1000L) =
        ThreatAssessment(
            score = 0.9f,
            level = level,
            categories = mapOf(Category.ROOT to 0.9f),
            evidence = listOf(Evidence("root.su_binary", 0.6f)),
            timestampMs = timestampMs,
        )

    private fun newSink(
        queue: TelemetryQueue,
        uploader: TelemetryUploader,
        scheduler: ManualScheduler,
        config: TelemetryQueueConfig = TelemetryQueueConfig(batchSize = 10),
        redact: (TelemetryEvent) -> TelemetryEvent? = { it },
    ) = QueuedTelemetrySink(queue, uploader, scheduler, config, redact)

    @Test
    fun report_skips_levels_below_minimum() {
        val queue = TelemetryQueue(InMemoryStore())
        val scheduler = ManualScheduler()
        val sink = newSink(queue, CollectingUploader(), scheduler)

        sink.report(assessment(level = Level.NONE))
        scheduler.runAll()

        assertEquals(0, queue.size())
    }

    @Test
    fun uploads_all_batches_and_empties_queue() {
        val queue = TelemetryQueue(InMemoryStore(), maxEvents = 100)
        val uploader = CollectingUploader()
        val scheduler = ManualScheduler()
        val sink = newSink(queue, uploader, scheduler)

        repeat(15) { index -> sink.report(assessment(timestampMs = (index + 1) * 10L)) }
        scheduler.runAll()

        assertEquals(0, queue.size())
        assertEquals(2, uploader.batches.size)
        assertEquals(10, uploader.batches[0].size)
        assertEquals(5, uploader.batches[1].size)
    }

    @Test
    fun failed_upload_retries_with_backoff_and_keeps_events() {
        val queue = TelemetryQueue(InMemoryStore(), maxEvents = 100)
        val uploader = CollectingUploader(failTimes = 1)
        val scheduler = ManualScheduler()
        val sink = newSink(queue, uploader, scheduler)

        sink.report(assessment())
        scheduler.runAll()

        assertEquals(0, queue.size())
        assertEquals(1, uploader.batches.size)
        assertEquals(listOf(60_000L), scheduler.scheduledDelays)
    }

    @Test
    fun redact_can_drop_events() {
        val queue = TelemetryQueue(InMemoryStore())
        val scheduler = ManualScheduler()
        val sink = newSink(queue, CollectingUploader(), scheduler, redact = { null })

        sink.report(assessment())
        scheduler.runAll()

        assertEquals(0, queue.size())
    }

    @Test
    fun timestamp_from_assessment_is_preserved() {
        val queue = TelemetryQueue(InMemoryStore())
        val uploader = CollectingUploader()
        val scheduler = ManualScheduler()
        val sink = newSink(queue, uploader, scheduler)

        sink.report(assessment(timestampMs = 4242L))
        scheduler.runAll()

        assertEquals(4242L, uploader.batches.single().single().timestampMs)
    }

    @Test
    fun concurrent_flush_now_is_idempotent() {
        val queue = TelemetryQueue(InMemoryStore())
        val uploader = CollectingUploader()
        val scheduler = ManualScheduler()
        val sink = newSink(queue, uploader, scheduler)

        sink.report(assessment())
        sink.flushNow()
        sink.flushNow()

        assertEquals(0, queue.size())
        assertTrue(uploader.batches.size <= 1)
    }
}

internal class InMemoryStore : TelemetryStore {
    private var lines: List<String> = emptyList()

    override fun load(): List<String> = lines

    override fun replaceAll(lines: List<String>) {
        this.lines = lines
    }
}

internal class ManualScheduler : TelemetryScheduler {
    private val tasks = ArrayDeque<() -> Unit>()
    val scheduledDelays = mutableListOf<Long>()

    override fun execute(task: () -> Unit) {
        tasks.addLast(task)
    }

    override fun schedule(delayMs: Long, task: () -> Unit) {
        scheduledDelays += delayMs
        tasks.addLast(task)
    }

    fun runAll(limit: Int = 100) {
        var executed = 0
        while (tasks.isNotEmpty() && executed < limit) {
            tasks.removeFirst().invoke()
            executed++
        }
    }
}
