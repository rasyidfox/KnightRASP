package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.AttestationProbe

/**
 * Hardware-backed key attestation (AndroidKeyStore TEE/StrongBox).
 *
 * Client-side this only reads the `RootOfTrust` fields (`deviceLocked`,
 * `verifiedBootState`) as a signal. The full certificate chain must be verified
 * by the backend against Google's roots — use
 * `Rasp.requestKeyAttestation(nonce)` to obtain it. Runs on the HIGH cost tier
 * (key generation) and is therefore cached by the engine.
 *
 * On devices without attestation support (API < 24, no TEE) the check reports
 * Unknown; software-level attestation is treated as Unknown because it carries
 * no hardware guarantee.
 */
class KeyAttestationCheck(private val attestation: AttestationProbe?) : RaspCheck {

    override val id = "integrity.key_attestation"
    override val category = Category.INTEGRITY
    override val cost = Cost.HIGH

    override fun run(ctx: RaspContext): CheckResult {
        val probe = attestation ?: return CheckResult.Unknown("attestation unavailable")
        val result = probe.attest(null) ?: return CheckResult.Unknown("key attestation failed")
        if (!result.hardwareBacked) {
            return CheckResult.Unknown("software attestation only")
        }

        val evidence = mutableListOf<Evidence>()
        if (result.deviceLocked == false) {
            evidence += Evidence(id, DEVICE_UNLOCKED_CONFIDENCE, "deviceLocked=false (hardware attestation)")
        }
        if (result.verifiedBootState != null && result.verifiedBootState != VERIFIED_BOOT_STATE_OK) {
            evidence += Evidence(
                id,
                BOOT_STATE_CONFIDENCE,
                "verifiedBootState=${result.verifiedBootState} (hardware attestation)",
            )
        }
        return if (evidence.isEmpty()) CheckResult.Clean else CheckResult.Detected(evidence)
    }

    companion object {
        const val DEVICE_UNLOCKED_CONFIDENCE = 0.6f
        const val BOOT_STATE_CONFIDENCE = 0.5f
        const val VERIFIED_BOOT_STATE_OK = 0
    }
}
