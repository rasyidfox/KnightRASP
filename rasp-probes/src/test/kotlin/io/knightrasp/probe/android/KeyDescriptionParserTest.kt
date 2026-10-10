package io.knightrasp.probe.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyDescriptionParserTest {

    // --- minimal DER builder -------------------------------------------------

    private fun length(size: Int): ByteArray =
        if (size < 0x80) byteArrayOf(size.toByte())
        else error("test fixtures stay below 128 bytes")

    private fun tlv(tag: Byte, value: ByteArray): ByteArray =
        byteArrayOf(tag) + length(value.size) + value

    private fun sequence(vararg parts: ByteArray): ByteArray =
        tlv(0x30, parts.fold(ByteArray(0)) { acc, part -> acc + part })

    private fun integer(value: Int) = tlv(0x02, byteArrayOf(value.toByte()))
    private fun enumerated(value: Int) = tlv(0x0A, byteArrayOf(value.toByte()))
    private fun bool(value: Boolean) = tlv(0x01, byteArrayOf(if (value) 0xFF.toByte() else 0x00))
    private fun octet(value: String) = tlv(0x04, value.toByteArray())

    private fun contextTag(tag: Int, value: ByteArray): ByteArray {
        val first = (0x80 or 0x20 or 0x1F).toByte()
        val chunks = mutableListOf<Int>()
        var rest = tag
        while (rest > 0) {
            chunks.add(0, rest and 0x7F)
            rest = rest shr 7
        }
        val tagBytes = byteArrayOf(first) +
            chunks.mapIndexed { index, chunk ->
                if (index < chunks.size - 1) (chunk or 0x80).toByte() else chunk.toByte()
            }.toByteArray()
        return tagBytes + length(value.size) + value
    }

    private fun keyDescription(
        deviceLocked: Boolean,
        verifiedBootState: Int,
        securityLevel: Int,
    ): ByteArray {
        // RootOfTrust (tag 704): untagged fields in order:
        // verifiedBootKey OCTET_STRING, deviceLocked BOOLEAN,
        // verifiedBootState ENUMERATED, verifiedBootHash OCTET_STRING.
        val rootOfTrust = contextTag(
            704,
            sequence(
                octet("b".repeat(32)),
                bool(deviceLocked),
                enumerated(verifiedBootState),
                octet("h".repeat(32)),
            ),
        )
        return sequence(
            integer(3),
            enumerated(securityLevel),
            integer(4),
            enumerated(securityLevel),
            octet("challenge"),
            octet(""),
            sequence(),
            sequence(rootOfTrust),
        )
    }

    private fun extensionValue(description: ByteArray) = tlv(0x04, description)

    // --- tests ---------------------------------------------------------------

    @Test
    fun parses_unlocked_device_from_tee_attestation() {
        val parsed = KeyDescriptionParser.parseExtensionValue(
            extensionValue(keyDescription(deviceLocked = false, verifiedBootState = 2, securityLevel = 1)),
        )

        assertEquals(1, parsed.securityLevel)
        assertFalse(parsed.deviceLocked!!)
        assertEquals(2, parsed.verifiedBootState)
    }

    @Test
    fun parses_locked_verified_device() {
        val parsed = KeyDescriptionParser.parseExtensionValue(
            extensionValue(keyDescription(deviceLocked = true, verifiedBootState = 0, securityLevel = 1)),
        )

        assertTrue(parsed.deviceLocked!!)
        assertEquals(0, parsed.verifiedBootState)
    }

    @Test
    fun software_attestation_reports_software_level() {
        val parsed = KeyDescriptionParser.parseExtensionValue(
            extensionValue(keyDescription(deviceLocked = false, verifiedBootState = 2, securityLevel = 0)),
        )

        assertEquals(0, parsed.securityLevel)
    }

    @Test
    fun garbage_extension_fails_closed() {
        val parsed = KeyDescriptionParser.parseExtensionValue(byteArrayOf(0x04, 0x02, 0x01, 0x02))

        assertEquals(0, parsed.securityLevel)
        assertEquals(null, parsed.deviceLocked)
        assertEquals(null, parsed.verifiedBootState)
    }

    @Test
    fun empty_extension_fails_closed() {
        val parsed = KeyDescriptionParser.parseExtensionValue(ByteArray(0))

        assertEquals(0, parsed.securityLevel)
        assertEquals(null, parsed.verifiedBootState)
    }
}
