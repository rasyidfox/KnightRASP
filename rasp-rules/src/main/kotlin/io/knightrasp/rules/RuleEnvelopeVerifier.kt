package io.knightrasp.rules

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Memverifikasi envelope rules: `payload` (JSON string) ditandatangani ECDSA P-256.
 *
 * Envelope tidak berisi kode; payload di-parse sebagai data oleh [RuleCodec]. Jadi
 * kompromi server tidak berubah menjadi remote code execution di perangkat.
 */
class RuleEnvelopeVerifier(publicKeyDerBase64: String) {

    private val publicKey: PublicKey = parsePublicKey(publicKeyDerBase64)

    fun verify(payload: String, signatureBase64: String): Boolean = try {
        val signature = Signature.getInstance(ALGORITHM)
        signature.initVerify(publicKey)
        signature.update(payload.toByteArray(Charsets.UTF_8))
        signature.verify(Base64Codec.decode(signatureBase64))
    } catch (_: Exception) {
        false
    }

    companion object {
        const val ALGORITHM = "SHA256withECDSA"

        fun parsePublicKey(derBase64: String): PublicKey {
            val der = Base64Codec.decode(derBase64.trim())
            return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
        }
    }
}
