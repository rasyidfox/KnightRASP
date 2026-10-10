package io.knightrasp.check.virtualization

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VirtualizationChecksTest {

    @Test
    fun cloner_clean_when_no_cloner_installed() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, ClonerPackagesCheck(probes.packages).run(testContext(probes)))
    }

    @Test
    fun cloner_detected_when_installed() {
        val probes = TestProbes()
        probes.packages.installed += "com.lbe.parallel"
        val result = ClonerPackagesCheck(probes.packages).run(testContext(probes))
        val detected = result as CheckResult.Detected
        assertEquals(1, detected.evidence.size)
    }

    @Test
    fun process_unknown_when_cmdline_unreadable() {
        val probes = TestProbes()
        assertTrue(
            SuspiciousProcessNameCheck(probes.proc).run(testContext(probes)) is CheckResult.Unknown
        )
    }

    @Test
    fun process_clean_for_normal_name() {
        val probes = TestProbes()
        probes.proc.cmdline = "io.knightrasp.test"
        assertEquals(
            CheckResult.Clean,
            SuspiciousProcessNameCheck(probes.proc).run(testContext(probes)),
        )
    }

    @Test
    fun process_detected_for_parallel_space_name() {
        val probes = TestProbes()
        probes.proc.cmdline = "com.lbe.parallel:vPlayer"
        val result = SuspiciousProcessNameCheck(probes.proc).run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }

    @Test
    fun process_clean_when_name_equals_package_even_with_marker() {
        val probes = TestProbes()
        probes.proc.cmdline = "io.knightrasp.parallel.test"
        assertEquals(
            CheckResult.Clean,
            SuspiciousProcessNameCheck(probes.proc).run(testContext(probes, packageName = "io.knightrasp.parallel.test")),
        )
    }
}
