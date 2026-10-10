package io.knightrasp.core

import io.knightrasp.check.CheckResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class TtlCacheTest {

    @Test
    fun returns_value_before_expiry() {
        var now = 1_000L
        val cache = TtlCache { now }
        cache.put("a", CheckResult.Clean, ttlMs = 100L)

        now = 1_099L
        assertSame(CheckResult.Clean, cache.get("a", 100L))
    }

    @Test
    fun expires_after_ttl() {
        var now = 1_000L
        val cache = TtlCache { now }
        cache.put("a", CheckResult.Detected(emptyList()), ttlMs = 100L)

        now = 1_100L
        assertNull(cache.get("a", 100L))
    }

    @Test
    fun clear_removes_entries() {
        val cache = TtlCache { 0L }
        cache.put("a", CheckResult.Clean, ttlMs = 1_000L)
        cache.clear()
        assertNull(cache.get("a", 1_000L))
    }

    @Test
    fun different_keys_are_independent() {
        val cache = TtlCache { 0L }
        cache.put("a", CheckResult.Clean, ttlMs = 1_000L)
        cache.put("b", CheckResult.Unknown("x"), ttlMs = 1_000L)
        assertEquals(CheckResult.Unknown("x"), cache.get("b", 1_000L))
    }
}
