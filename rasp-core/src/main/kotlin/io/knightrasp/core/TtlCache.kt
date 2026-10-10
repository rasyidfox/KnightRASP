package io.knightrasp.core

import io.knightrasp.check.CheckResult
import java.util.concurrent.ConcurrentHashMap

/** Cache hasil check per id dengan TTL; dipakai agar scan berulang tidak mengulang kerja mahal. */
class TtlCache(private val clock: () -> Long = System::currentTimeMillis) {

    private class Entry(val result: CheckResult, val expiresAtMs: Long)

    private val entries = ConcurrentHashMap<String, Entry>()

    fun get(key: String, ttlMs: Long): CheckResult? {
        val entry = entries[key] ?: return null
        if (clock() >= entry.expiresAtMs) {
            entries.remove(key, entry)
            return null
        }
        return entry.result
    }

    fun put(key: String, result: CheckResult, ttlMs: Long) {
        entries[key] = Entry(result, clock() + ttlMs)
    }

    fun clear() {
        entries.clear()
    }
}
