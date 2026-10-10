package io.knightrasp.check.emulator

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EmulatorCpuInfoCheckTest {

    @Test
    fun unknown_when_cpuinfo_unreadable() {
        val probes = TestProbes()
        assertTrue(EmulatorCpuInfoCheck(probes.file).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun clean_on_physical_device() {
        val probes = TestProbes()
        probes.file.add("/proc/cpuinfo", "Hardware\t: Qualcomm Technologies, Inc SM8550\n")
        assertEquals(
            CheckResult.Clean,
            EmulatorCpuInfoCheck(probes.file).run(testContext(probes)),
        )
    }

    @Test
    fun detected_on_emulator() {
        val probes = TestProbes()
        probes.file.add(
            "/proc/cpuinfo",
            "Hardware\t: ranchu\nmodel name\t: Android virtual processor\n",
        )
        val result = EmulatorCpuInfoCheck(probes.file).run(testContext(probes))
        val detected = result as CheckResult.Detected
        assertTrue(detected.evidence.isNotEmpty())
    }
}
