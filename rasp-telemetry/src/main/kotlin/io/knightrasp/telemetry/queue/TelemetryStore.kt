package io.knightrasp.telemetry.queue

import java.io.File

/** Telemetry JSON-line storage. Implementations must be safe to call across threads. */
interface TelemetryStore {
    fun load(): List<String>

    fun replaceAll(lines: List<String>)
}

/**
 * File-based store (JSON Lines). Writes through a temporary file then renames, and
 * swallows I/O errors (fail-open: telemetry must not disturb the app).
 */
class FileTelemetryStore(private val file: File) : TelemetryStore {

    override fun load(): List<String> = try {
        if (!file.exists()) {
            emptyList()
        } else {
            file.readLines(Charsets.UTF_8).filter { it.isNotBlank() }
        }
    } catch (_: Exception) {
        emptyList()
    }

    override fun replaceAll(lines: List<String>) {
        try {
            val parent = file.absoluteFile.parentFile
            parent.mkdirs()
            val tmp = File(parent, file.name + ".tmp")
            tmp.writeText(
                lines.joinToString(separator = "\n", postfix = if (lines.isEmpty()) "" else "\n"),
                Charsets.UTF_8,
            )
            if (!tmp.renameTo(file)) {
                file.writeText(tmp.readText(Charsets.UTF_8), Charsets.UTF_8)
                tmp.delete()
            }
        } catch (_: Exception) {
            // fail-open
        }
    }
}
