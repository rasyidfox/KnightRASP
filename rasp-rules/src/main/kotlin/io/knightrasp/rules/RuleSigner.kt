package io.knightrasp.rules

import java.security.PrivateKey
import java.security.Signature
import org.json.JSONObject

/**
 * Penandatangan envelope rules. Dipakai di sisi server/penerbit rules.
 *
 * Modul klien hanya memerlukan public key (lihat [RuleEnvelopeVerifier]); private key
 * tidak pernah dikirim ke perangkat.
 */
class RuleSigner(privateKey: PrivateKey) {

    private val privateKey: PrivateKey = privateKey

    fun sign(payload: String): String {
        val signature = Signature.getInstance(RuleEnvelopeVerifier.ALGORITHM)
        signature.initSign(privateKey)
        signature.update(payload.toByteArray(Charsets.UTF_8))
        return Base64Codec.encode(signature.sign())
    }

    fun envelopeFor(payload: String): String = envelope(payload, sign(payload))

    companion object {
        fun envelope(payload: String, signatureBase64: String): String = JSONObject()
            .put("payload", payload)
            .put("sig", signatureBase64)
            .toString()
    }
}
