package io.knightrasp.rules

import io.knightrasp.config.RaspRules
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/**
 * Memuat rules dari envelope, file, atau URL; selalu memverifikasi tanda tangan dan
 * masa berlaku. Kegagalan apa pun menghasilkan `null` (fail-open: pakai rules lokal /
 * config statis).
 */
class SignedRulesLoader(private val verifier: RuleEnvelopeVerifier) {

    fun loadEnvelope(envelopeJson: String, nowMs: Long): RaspRules? = try {
        val envelope = JSONObject(envelopeJson)
        val payload = envelope.optString("payload", null)
        val signature = envelope.optString("sig", null)
        when {
            payload.isNullOrBlank() || signature.isNullOrBlank() -> null
            !verifier.verify(payload, signature) -> null
            else -> RuleCodec.parse(payload).takeIf { !it.isExpired(nowMs) }
        }
    } catch (_: Exception) {
        null
    }

    fun loadFromFile(file: File, nowMs: Long): RaspRules? = try {
        loadEnvelope(file.readText(Charsets.UTF_8), nowMs)
    } catch (_: Exception) {
        null
    }

    fun loadFromUrl(
        url: String,
        nowMs: Long,
        connectTimeoutMs: Int = 5_000,
        readTimeoutMs: Int = 5_000,
    ): RaspRules? = try {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
        }
        try {
            val body = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            loadEnvelope(body, nowMs)
        } finally {
            connection.disconnect()
        }
    } catch (_: Exception) {
        null
    }
}
