package io.knightrasp.check.debug

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestNativeProbe
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeDebuggerCheckTest {

    @Test
    fun unknown_when_native_probe_unavailable() {
        val probes = TestProbes(native = null)
        assertTrue(NativeDebuggerCheck(probes.native).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun clean_when_native_reports_no_debugger() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, NativeDebuggerCheck(probes.native).run(testContext(probes)))
    }

    @Test
    fun detected_when_native_reports_debugger() {
        val native = TestNativeProbe().apply { debuggerDetected = true }
        val probes = TestProbes(native = native)
        val result = NativeDebuggerCheck(probes.native).run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }
}
