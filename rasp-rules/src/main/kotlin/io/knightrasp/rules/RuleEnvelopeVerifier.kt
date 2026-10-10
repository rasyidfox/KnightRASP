package io.knightrasp.rules

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Verifies rules envelopes: the `payload` (JSON string) is signed with ECDSA P-256.
 *
 * The envelope carries no code; the payload is parsed as data by [RuleCodec]. So
 * a server compromise does not turn into remote code execution on the device.
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
