package io.knightrasp.check.environment

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Test

class EnvironmentChecksTest {

    @Test
    fun adb_clean_by_default() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, AdbEnabledCheck(probes.settings).run(testContext(probes)))
    }

    @Test
    fun adb_detected_when_enabled() {
        val probes = TestProbes()
        probes.settings.global[AdbEnabledCheck.KEY_ADB_ENABLED] = 1
        val result = AdbEnabledCheck(probes.settings).run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }

    @Test
    fun developer_options_detected() {
        val probes = TestProbes()
        probes.settings.global[DeveloperOptionsCheck.KEY_DEVELOPMENT_SETTINGS_ENABLED] = 1
        val result = DeveloperOptionsCheck(probes.settings).run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }

    @Test
    fun mock_location_detected() {
        val probes = TestProbes()
        probes.settings.secure[MockLocationCheck.KEY_MOCK_LOCATION] = 1
        val result = MockLocationCheck(probes.settings).run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }
}
