package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRootChecksTest {

    @Test
    fun mount_check_unknown_without_native() {
        val probes = TestProbes(native = null)
        assertTrue(RootMountCheck(probes.native).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun mount_check_clean_by_default() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, RootMountCheck(probes.native).run(testContext(probes)))
    }

    @Test
    fun mount_check_detected_when_mounts_visible() {
        val native = io.knightrasp.testing.TestNativeProbe().apply { mountsDetected = true }
        val probes = TestProbes(native = native)
        assertEquals(
            CheckResult.Detected::class.java,
            RootMountCheck(probes.native).run(testContext(probes)).javaClass,
        )
    }

    @Test
    fun bootloader_check_unknown_without_native() {
        val probes = TestProbes(native = null)
        assertTrue(BootloaderStateCheck(probes.native).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun bootloader_check_clean_by_default() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, BootloaderStateCheck(probes.native).run(testContext(probes)))
    }

    @Test
    fun bootloader_check_detected_when_modified() {
        val native = io.knightrasp.testing.TestNativeProbe().apply { bootStateModified = true }
        val probes = TestProbes(native = native)
        assertEquals(
            CheckResult.Detected::class.java,
            BootloaderStateCheck(probes.native).run(testContext(probes)).javaClass,
        )
    }
}
