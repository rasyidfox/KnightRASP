package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestNativeProbe
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeHookCheckTest {

    @Test
    fun unknown_when_native_probe_unavailable() {
        val probes = TestProbes(native = null)
        assertTrue(NativeHookCheck(probes.native).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun clean_when_native_reports_no_hook() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, NativeHookCheck(probes.native).run(testContext(probes)))
    }

    @Test
    fun detected_when_native_reports_hook() {
        val native = TestNativeProbe().apply { hooked = true }
        val probes = TestProbes(native = native)
        val result = NativeHookCheck(probes.native).run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }

    @Test
    fun injected_memory_unknown_without_native() {
        val probes = TestProbes(native = null)
        assertTrue(InjectedMemoryCheck(probes.native).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun injected_memory_clean_by_default() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, InjectedMemoryCheck(probes.native).run(testContext(probes)))
    }

    @Test
    fun injected_memory_detected_when_shape_matches() {
        val native = TestNativeProbe().apply { injectedMemory = true }
        val probes = TestProbes(native = native)
        assertEquals(
            CheckResult.Detected::class.java,
            InjectedMemoryCheck(probes.native).run(testContext(probes)).javaClass,
        )
    }
}
