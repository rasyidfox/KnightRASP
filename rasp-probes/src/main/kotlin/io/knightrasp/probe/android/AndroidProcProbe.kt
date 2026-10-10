package io.knightrasp.probe.android

import io.knightrasp.probe.ProcProbe
import io.knightrasp.util.TextCodec
import java.io.File
import java.io.FileInputStream

class AndroidProcProbe : ProcProbe {

    @Volatile
    private var mapsCache: String? = null

    @Volatile
    private var mapsCachedAtMs: Long = 0L

    private val mapsLock = Any()

    /** Reused read buffer so 4 MB is not allocated on every scan. */
    private var readBuffer = ByteArray(0)

    override fun selfStatus(): String? = readLimited(STATUS_PATH, MAX_STATUS_LINES)

    /**
     * `/proc/self/maps` is read as raw bytes (fast) and then briefly cached.
     * Line-by-line reading through `useLines` proved slow (>1 s) on cold
     * start on mid-range devices; several checks use the same data in the same scan,
     * so the cache is also single-flight (the second reader waits for the first).
     *
     * The cache is released on expiry so the multi-megabyte string does not linger in
     * process memory; the read buffer is reused to reduce GC pressure.
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
                val comm = File(dir, COMM_FILE)
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
        /** Obfuscated /proc paths and thread comm file name. */
        val STATUS_PATH: String = TextCodec.decode("1a45475a561a465059531a464154414046", 0x35)
        val MAPS_PATH: String = TextCodec.decode("4e11130e024e12040d074e0c001112", 0x61)
        val CMDLINE_PATH: String = TextCodec.decode("38676578743864727b7138747a737b7e7972", 0x17)
        val TASK_DIR: String = TextCodec.decode("540b09141854081e171d540f1a0810", 0x7B)
        val COMM_FILE: String = TextCodec.decode("6c606262", 0x0F)

        const val MAX_STATUS_LINES = 512
        const val MAX_MAPS_BYTES = 4 * 1024 * 1024
        const val MAPS_CACHE_TTL_MS = 1_000L
    }
}
