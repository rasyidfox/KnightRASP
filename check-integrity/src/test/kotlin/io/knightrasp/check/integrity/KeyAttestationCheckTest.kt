package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.model.KeyAttestationResult
import io.knightrasp.testing.TestAttestationProbe
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyAttestationCheckTest {

    private fun result(
        securityLevel: Int = 1,
        deviceLocked: Boolean? = true,
        verifiedBootState: Int? = 0,
    ) = KeyAttestationResult(
        nonce = null,
        certificateChain = emptyList(),
        securityLevel = securityLevel,
        deviceLocked = deviceLocked,
        verifiedBootState = verifiedBootState,
    )

    @Test
    fun unknown_without_attestation_probe() {
        val probes = TestProbes(attestation = null)
        assertTrue(KeyAttestationCheck(probes.attestation).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun unknown_when_attestation_fails() {
        val probe = TestAttestationProbe().apply { result = null }
        val probes = TestProbes(attestation = probe)
        assertTrue(KeyAttestationCheck(probes.attestation).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun unknown_on_software_attestation() {
        val probe = TestAttestationProbe().apply { result = result(securityLevel = 0, deviceLocked = false) }
        val probes = TestProbes(attestation = probe)
        assertTrue(KeyAttestationCheck(probes.attestation).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun clean_on_locked_verified_hardware_device() {
        val probe = TestAttestationProbe().apply { result = result() }
        val probes = TestProbes(attestation = probe)
        assertEquals(CheckResult.Clean, KeyAttestationCheck(probes.attestation).run(testContext(probes)))
    }

    @Test
    fun detected_when_device_locked_is_false() {
        val probe = TestAttestationProbe().apply { result = result(deviceLocked = false, verifiedBootState = 2) }
        val probes = TestProbes(attestation = probe)
        val result = KeyAttestationCheck(probes.attestation).run(testContext(probes))
        val detected = result as CheckResult.Detected
        assertEquals(2, detected.evidence.size)
    }

    @Test
    fun detected_when_verified_boot_state_is_not_verified() {
        val probe = TestAttestationProbe().apply { result = result(deviceLocked = true, verifiedBootState = 2) }
        val probes = TestProbes(attestation = probe)
        val result = KeyAttestationCheck(probes.attestation).run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }
}
