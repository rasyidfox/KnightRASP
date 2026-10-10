package io.knightrasp.check.emulator

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EmulatorPropsCheckTest {

    @Test
    fun clean_on_physical_device() {
        val probes = TestProbes()
        probes.system.manufacturer = "Google"
        probes.system.model = "Pixel 8"
        probes.system.hardware = "shiba"
        probes.system.product = "shiba"
        probes.system.fingerprint = "google/shiba/shiba:14/UQ1A/11228899:user/release-keys"

        val result = EmulatorPropsCheck(probes.system).run(testContext(probes))

        assertEquals(CheckResult.Clean, result)
    }

    @Test
    fun detected_on_emulator() {
        val probes = TestProbes()
        probes.system.manufacturer = "Google"
        probes.system.model = "sdk_gphone64_x86_64"
        probes.system.hardware = "ranchu"
        probes.system.product = "sdk_gphone64_x86_64"
        probes.system.fingerprint = "google/sdk_gphone64_x86_64/emulator64_x86_64:12/SE1A.220203.002"
        probes.system.supportedAbis = listOf("x86_64", "arm64-v8a")

        val result = EmulatorPropsCheck(probes.system).run(testContext(probes))

        val detected = result as CheckResult.Detected
        assertTrue(detected.evidence.size >= 2)
    }
}
