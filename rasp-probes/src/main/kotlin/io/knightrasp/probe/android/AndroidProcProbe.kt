package io.knightrasp.probe.android

import io.knightrasp.probe.ProcProbe
import java.io.File
import java.io.FileInputStream

class AndroidProcProbe : ProcProbe {

    @Volatile
    private var mapsCache: String? = null

    @Volatile
    private var mapsCachedAtMs: Long = 0L

    private val mapsLock = Any()

    /** Buffer baca yang dipakai ulang agar tidak alokasi 4 MB setiap scan. */
    private var readBuffer = ByteArray(0)

    override fun selfStatus(): String? = readLimited(STATUS_PATH, MAX_STATUS_LINES)

    /**
     * `/proc/self/maps` dibaca sebagai byte mentah (cepat) lalu di-cache singkat.
     * Pembacaan baris-per-baris lewat `useLines` terbukti lambat (>1 dtk) saat cold
     * start di device mid-range; beberapa check memakai data yang sama di scan yang sama,
     * jadi cache-nya juga single-flight (pembaca kedua menunggu pembaca pertama).
     *
     * Cache dilepas saat kedaluwarsa supaya string multi-megabyte tidak menetap di
     * memori proses; buffer baca dipakai ulang untuk menekan tekanan GC.
     */
    override fun selfMaps(): String? {
        val now = System.currentTimeMillis()
        val cached = mapsCache
        if (cached != null && now - mapsCachedAtMs < MAPS_CACHE_TTL_MS) {
            return cached
        }
        synchronized(mapsLock) {
            val recheckAt = System.currentTimeMillis()
            val recheck = mapsCache
            if (recheck != null && recheckAt - mapsCachedAtMs < MAPS_CACHE_TTL_MS) {
                return recheck
            }
            mapsCache = null
            val buffer = obtainBuffer()
            val total = readInto(buffer, MAPS_PATH)
            val fresh = if (total <= 0) null else String(buffer, 0, total, Charsets.UTF_8)
            mapsCache = fresh
            mapsCachedAtMs = System.currentTimeMillis()
            return fresh
        }
    }

    override fun selfCmdline(): String? = try {
        val file = File(CMDLINE_PATH)
        if (!file.exists()) {
            null
        } else {
            file.readText(Charsets.UTF_8).substringBefore('\u0000').trim().ifEmpty { null }
        }
    } catch (_: Exception) {
        null
    }

    override fun threadNames(): List<String> = try {
        File(TASK_DIR).listFiles()
            ?.mapNotNull { dir ->
                val comm = File(dir, "comm")
                if (comm.exists()) comm.readText(Charsets.UTF_8).trim() else null
            }
            ?: emptyList()
    } catch (_: Exception) {
        emptyList()
    }

    private fun readLimited(path: String, maxLines: Int): String? = try {
        val file = File(path)
        if (!file.exists()) {
            null
        } else {
            file.useLines { lines -> lines.take(maxLines).joinToString("\n") }
        }
    } catch (_: Exception) {
        null
    }

    private fun obtainBuffer(): ByteArray {
        if (readBuffer.size < MAX_MAPS_BYTES) {
            readBuffer = ByteArray(MAX_MAPS_BYTES)
        }
        return readBuffer
    }

    private fun readInto(buffer: ByteArray, path: String): Int = try {
        val file = File(path)
        if (!file.exists()) {
            -1
        } else {
            FileInputStream(file).use { input ->
                var total = 0
                while (total < buffer.size) {
                    val read = input.read(buffer, total, buffer.size - total)
                    if (read <= 0) {
                        break
                    }
                    total += read
                }
                total
            }
        }
    } catch (_: Exception) {
        -1
    }

    private companion object {
        const val STATUS_PATH = "/proc/self/status"
        const val MAPS_PATH = "/proc/self/maps"
        const val CMDLINE_PATH = "/proc/self/cmdline"
        const val TASK_DIR = "/proc/self/task"
        const val MAX_STATUS_LINES = 512
        const val MAX_MAPS_BYTES = 4 * 1024 * 1024
        const val MAPS_CACHE_TTL_MS = 1_000L
    }
}
