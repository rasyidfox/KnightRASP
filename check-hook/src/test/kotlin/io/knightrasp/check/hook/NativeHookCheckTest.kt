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
}
