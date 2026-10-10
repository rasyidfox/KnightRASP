package io.knightrasp.check.debug

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TracerPidCheckTest {

    @Test
    fun clean_when_tracer_pid_is_zero() {
        val probes = TestProbes()
        probes.proc.status = "Name:\tio.knightrasp.test\nTracerPid:\t0\n"
        val result = TracerPidCheck(probes.proc).run(testContext(probes))
        assertEquals(CheckResult.Clean, result)
    }

    @Test
    fun detected_when_tracer_pid_is_set() {
        val probes = TestProbes()
        probes.proc.status = "Name:\tio.knightrasp.test\nTracerPid:\t4242\n"
        val result = TracerPidCheck(probes.proc).run(testContext(probes))
        val detected = result as CheckResult.Detected
        assertTrue(detected.evidence.single().detail!!.contains("4242"))
    }

    @Test
    fun unknown_when_status_unreadable() {
        val probes = TestProbes()
        val result = TracerPidCheck(probes.proc).run(testContext(probes))
        assertTrue(result is CheckResult.Unknown)
    }
}
