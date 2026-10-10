package io.knightrasp.model

/**
 * Result of a hardware-backed key attestation (AndroidKeyStore + attestation
 * challenge). The certificate chain is meant to be verified **on the server**
 * against Google's root certificates; the parsed fields are client-side signals
 * only and must not be trusted as final proof.
 *
 * @param nonce the challenge that was passed in (echoed back for anti-replay checks).
 * @param certificateChain DER-encoded certificate chain, leaf first.
 * @param securityLevel where the key lives: 0 = software, 1 = TEE, 2 = StrongBox.
 * @param deviceLocked `RootOfTrust.deviceLocked` from the attestation extension;
 *   `false` means the bootloader is unlocked. Null when absent/unparsable.
 * @param verifiedBootState `RootOfTrust.verifiedBootState`: 0 = verified,
 *   1 = self-signed, 2 = unverified, 3 = failed. Null when absent/unparsable.
 */
data class KeyAttestationResult(
    val nonce: String?,
    val certificateChain: List<ByteArray>,
    val securityLevel: Int,
    val deviceLocked: Boolean?,
    val verifiedBootState: Int?,
) {
    val hardwareBacked: Boolean get() = securityLevel >= 1
}

/** Callback for [io.knightrasp.Rasp.requestKeyAttestation]. */
fun interface KeyAttestationCallback {
    /** Called on the main thread. Null when attestation is unavailable/failed. */
    fun onResult(result: KeyAttestationResult?)
}
