package io.knightrasp.probe.android

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.knightrasp.model.KeyAttestationResult
import io.knightrasp.probe.AttestationProbe
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * [AttestationProbe] backed by AndroidKeyStore hardware attestation.
 *
 * A fresh ephemeral key is generated per call, because the attestation challenge
 * is only honored at key generation. The key is deleted right after the chain is
 * read. Requires API 24+; on devices without an attestation-capable TEE the call
 * fails and null is returned.
 */
class AndroidAttestationProbe : AttestationProbe {

    override fun attest(nonce: String?): KeyAttestationResult? {
        if (Build.VERSION.SDK_INT < 24) {
            return null
        }
        val alias = ALIAS_PREFIX + UUID.randomUUID()
        return try {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE,
            )
            // Some devices refuse to attest without a challenge, so one is always
            // set: the caller's nonce when provided, a random value otherwise.
            val challenge = nonce?.toByteArray(Charsets.UTF_8)
                ?: ByteArray(16).also { bytes -> SecureRandom().nextBytes(bytes) }
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val chain = keyStore.getCertificateChain(alias)?.map { it.encoded } ?: return null
            val leaf = keyStore.getCertificateChain(alias)?.firstOrNull() as? X509Certificate
                ?: return null
            val parsed = KeyDescriptionParser.parse(leaf)
            KeyAttestationResult(
                nonce = nonce,
                certificateChain = chain,
                securityLevel = parsed.securityLevel,
                deviceLocked = parsed.deviceLocked,
                verifiedBootState = parsed.verifiedBootState,
            )
        } catch (_: Throwable) {
            null
        } finally {
            runCatching {
                KeyStore.getInstance(ANDROID_KEYSTORE)
                    .apply { load(null) }
                    .deleteEntry(alias)
            }
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PREFIX = "kr-att-"
    }
}
