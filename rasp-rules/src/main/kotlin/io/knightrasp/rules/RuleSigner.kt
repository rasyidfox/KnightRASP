package io.knightrasp.rules

import java.security.PrivateKey
import java.security.Signature
import org.json.JSONObject

/**
 * Rules envelope signer. Used on the server/rules-publisher side.
 *
 * The client module only needs the public key (see [RuleEnvelopeVerifier]); the private key
 * is never sent to the device.
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
