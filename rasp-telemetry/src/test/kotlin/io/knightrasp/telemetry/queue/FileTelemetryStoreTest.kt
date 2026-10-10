package io.knightrasp.telemetry.queue

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class FileTelemetryStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    @Test
    fun write_and_read_roundtrip() {
        val store = FileTelemetryStore(temp.newFile("telemetry.jsonl"))

        store.replaceAll(listOf("a", "b"))

        assertEquals(listOf("a", "b"), store.load())

        store.replaceAll(emptyList())

        assertEquals(emptyList<String>(), store.load())
    }

    @Test
    fun missing_file_loads_empty_and_creates_directories() {
        val store = FileTelemetryStore(File(temp.root, "nested/dir/data.jsonl"))

        assertEquals(emptyList<String>(), store.load())

        store.replaceAll(listOf("x"))

        assertEquals(listOf("x"), store.load())
    }
}
