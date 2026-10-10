package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestNativeProbe
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HardwareHookChecksTest {

    @Test
    fun system_libraries_unknown_without_native() {
        val probes = TestProbes(native = null)
        assertTrue(
            SystemLibraryIntegrityCheck(probes.native).run(testContext(probes)) is CheckResult.Unknown
        )
    }

    @Test
    fun system_libraries_clean_by_default() {
        val probes = TestProbes()
        assertEquals(
            CheckResult.Clean,
            SystemLibraryIntegrityCheck(probes.native).run(testContext(probes)),
        )
    }

    @Test
    fun system_libraries_detected_when_modified() {
        val native = TestNativeProbe().apply { systemLibrariesModified = true }
        val probes = TestProbes(native = native)
        assertEquals(
            CheckResult.Detected::class.java,
            SystemLibraryIntegrityCheck(probes.native).run(testContext(probes)).javaClass,
        )
    }

    @Test
    fun plt_unknown_without_native() {
        val probes = TestProbes(native = null)
        assertTrue(PltIntegrityCheck(probes.native).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun plt_clean_by_default() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, PltIntegrityCheck(probes.native).run(testContext(probes)))
    }

    @Test
    fun plt_detected_when_redirected() {
        val native = TestNativeProbe().apply { pltHookDetected = true }
        val probes = TestProbes(native = native)
        assertEquals(
            CheckResult.Detected::class.java,
            PltIntegrityCheck(probes.native).run(testContext(probes)).javaClass,
        )
    }
}
