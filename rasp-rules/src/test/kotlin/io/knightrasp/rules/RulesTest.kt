package io.knightrasp.rules

import io.knightrasp.config.RaspRules
import io.knightrasp.config.Thresholds
import java.net.ServerSocket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RulesTest {

    private val keyPair: KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
    private val signer = RuleSigner(keyPair.private)
    private val verifier = RuleEnvelopeVerifier(
        Base64.getEncoder().encodeToString(keyPair.public.encoded)
    )
    private val loader = SignedRulesLoader(verifier)

    @Test
    fun base64_matches_java_implementation() {
        for (size in 0..64) {
            val bytes = ByteArray(size) { (it * 7 + 3).toByte() }
            assertEquals(Base64.getEncoder().encodeToString(bytes), Base64Codec.encode(bytes))
            assertArrayEquals(bytes, Base64Codec.decode(Base64Codec.encode(bytes)))
        }
        assertArrayEquals(
            "any + input".toByteArray(),
            Base64Codec.decode(Base64.getEncoder().encodeToString("any + input".toByteArray())),
        )
    }

    @Test
    fun codec_roundtrip_preserves_all_fields() {
        val rules = RaspRules(
            version = 3,
            issuedAtMs = 123L,
            expiresAtMs = 456L,
            disabledChecks = setOf("env.developer_options"),
            confidenceScale = mapOf("root.su_binary" to 0.5f),
            thresholds = Thresholds(low = 0.1f, medium = 0.2f, high = 0.3f),
        )

        val parsed = RuleCodec.parse(RuleCodec.encode(rules))

        assertEquals(rules.copy(signatureVerified = true), parsed)
    }

    @Test
    fun signed_envelope_verifies_and_loads() {
        val envelope = signer.envelopeFor(RuleCodec.encode(RaspRules(version = 7)))

        val rules = loader.loadEnvelope(envelope, nowMs = 0L)

        assertNotNull(rules)
        assertEquals(7, rules!!.version)
        assertTrue(rules.signatureVerified)
    }

    @Test
    fun tampered_payload_is_rejected() {
        val payload = RuleCodec.encode(RaspRules(version = 7))
        val signature = signer.sign(payload)
        val tamperedEnvelope = RuleSigner.envelope(payload + " ", signature)

        assertNull(loader.loadEnvelope(tamperedEnvelope, nowMs = 0L))
    }

    @Test
    fun signature_from_other_key_is_rejected() {
        val otherPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
            .generateKeyPair()
        val envelope = RuleSigner(otherPair.private)
            .envelopeFor(RuleCodec.encode(RaspRules(version = 7)))

        assertNull(loader.loadEnvelope(envelope, nowMs = 0L))
    }

    @Test
    fun expired_rules_are_rejected() {
        val envelope = signer.envelopeFor(
            RuleCodec.encode(RaspRules(version = 7, expiresAtMs = 100L))
        )

        assertNotNull(loader.loadEnvelope(envelope, nowMs = 100L))
        assertNull(loader.loadEnvelope(envelope, nowMs = 101L))
    }

    @Test
    fun malformed_envelope_is_rejected() {
        assertNull(loader.loadEnvelope("not json", nowMs = 0L))
        assertNull(loader.loadEnvelope("""{"payload":"x"}""", nowMs = 0L))
    }

    @Test
    fun loads_from_local_http_server() {
        val envelope = signer.envelopeFor(RuleCodec.encode(RaspRules(version = 9)))
        val url = serveOnce(envelope)

        val rules = loader.loadFromUrl(url, nowMs = 0L)

        assertEquals(9, rules?.version)
    }

    /** Minimal one-request HTTP server (no jdk.httpserver, which is absent from android.jar). */
    private fun serveOnce(body: String): String {
        val server = ServerSocket(0)
        Thread {
            runCatching {
                server.accept().use { socket ->
                    val reader = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
                    while (true) {
                        val line = reader.readLine() ?: break
                        if (line.isEmpty()) break
                    }
                    val bytes = body.toByteArray(Charsets.UTF_8)
                    val header = "HTTP/1.1 200 OK\r\n" +
                        "Content-Type: application/json\r\n" +
                        "Content-Length: ${bytes.size}\r\n" +
                        "Connection: close\r\n\r\n"
                    socket.getOutputStream().apply {
                        write(header.toByteArray(Charsets.US_ASCII))
                        write(bytes)
                        flush()
                    }
                }
            }
            runCatching { server.close() }
        }.start()
        return "http://127.0.0.1:${server.localPort}/rules"
    }
}
