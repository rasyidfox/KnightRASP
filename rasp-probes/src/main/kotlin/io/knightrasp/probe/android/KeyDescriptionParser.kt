package io.knightrasp.probe.android

import java.security.cert.X509Certificate

/**
 * Minimal DER parser for the Android key attestation extension
 * (OID 1.3.6.1.4.1.11129.2.1.17, "KeyDescription").
 *
 * Only the fields the SDK needs are extracted: attestation security level and,
 * inside the RootOfTrust authorization lists, `deviceLocked` and
 * `verifiedBootState`. Full chain verification against Google's roots is the
 * backend's job; this parser is a client-side signal only, so it is written to
 * fail closed (return nulls) rather than throw.
 */
internal object KeyDescriptionParser {

    const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    private const val TAG_SEQUENCE = 0x10
    private const val TAG_ENUMERATED = 0x0A
    private const val TAG_BOOLEAN = 0x01
    private const val TAG_OCTET_STRING = 0x04

    /** RootOfTrust lives at tag 704; inside it the fields are untagged. */
    private const val TAG_ROOT_OF_TRUST = 704

    data class Parsed(
        val securityLevel: Int,
        val deviceLocked: Boolean?,
        val verifiedBootState: Int?,
    )

    fun parse(certificate: X509Certificate): Parsed =
        parseExtensionValue(certificate.getExtensionValue(ATTESTATION_OID) ?: ByteArray(0))

    /** Parses the DER value returned by `X509Certificate.getExtensionValue`. */
    fun parseExtensionValue(extensionValue: ByteArray): Parsed {
        if (extensionValue.isEmpty()) {
            return Parsed(0, null, null)
        }
        return try {
            val octet = readTlv(extensionValue, 0)
            val description = readTlv(octet.value, 0)
            val fields = readAll(description.value)
            val securityLevel = fields.getOrNull(1)?.let { readInt(it.value) } ?: 0

            var deviceLocked: Boolean? = null
            var verifiedBootState: Int? = null
            // softwareEnforced / teeEnforced authorization lists
            for (index in 6..7) {
                val list = fields.getOrNull(index) ?: continue
                if (list.tag != TAG_SEQUENCE) continue
                for (entry in readAll(list.value)) {
                    if (entry.tag == TAG_ROOT_OF_TRUST) {
                        val rooted = parseRootOfTrust(entry.value)
                        if (rooted.deviceLocked != null) deviceLocked = rooted.deviceLocked
                        if (rooted.verifiedBootState != null) {
                            verifiedBootState = rooted.verifiedBootState
                        }
                    }
                }
            }
            Parsed(securityLevel, deviceLocked, verifiedBootState)
        } catch (_: Exception) {
            Parsed(0, null, null)
        }
    }

    private data class Tlv(val tag: Int, val value: ByteArray)

    private fun readAll(bytes: ByteArray): List<Tlv> {
        val result = ArrayList<Tlv>()
        var offset = 0
        while (offset < bytes.size) {
            val (tlv, next) = readTlvAt(bytes, offset)
            result += tlv
            offset = next
        }
        return result
    }

    private fun readTlv(bytes: ByteArray, offset: Int): Tlv = readTlvAt(bytes, offset).first

    private fun readTlvAt(bytes: ByteArray, start: Int): Pair<Tlv, Int> {
        var offset = start
        var tag = bytes[offset].toInt() and 0xFF
        offset++
        if (tag and 0x1F == 0x1F) {
            tag = 0
            while (true) {
                val next = bytes[offset].toInt() and 0xFF
                offset++
                tag = (tag shl 7) or (next and 0x7F)
                if (next and 0x80 == 0) break
            }
        } else {
            tag = tag and 0x1F
        }

        var length = bytes[offset].toInt() and 0xFF
        offset++
        if (length and 0x80 != 0) {
            val count = length and 0x7F
            length = 0
            repeat(count) {
                length = (length shl 8) or (bytes[offset].toInt() and 0xFF)
                offset++
            }
        }
        val value = bytes.copyOfRange(offset, offset + length)
        return Tlv(tag, value) to (offset + length)
    }

    private fun readInt(value: ByteArray): Int {
        var result = 0
        for (byte in value) {
            result = (result shl 8) or (byte.toInt() and 0xFF)
        }
        return result
    }

    /**
     * RootOfTrust is a SEQUENCE with untagged fields in order:
     * verifiedBootKey OCTET_STRING, deviceLocked BOOLEAN,
     * verifiedBootState ENUMERATED, verifiedBootHash OCTET_STRING.
     */
    private fun parseRootOfTrust(value: ByteArray): Parsed {
        var deviceLocked: Boolean? = null
        var verifiedBootState: Int? = null
        return try {
            val sequence = readTlv(value, 0)
            for (field in readAll(sequence.value)) {
                when (field.tag) {
                    TAG_BOOLEAN -> deviceLocked = readBoolean(field.value)
                    TAG_ENUMERATED -> verifiedBootState = readInt(field.value)
                }
            }
            Parsed(0, deviceLocked, verifiedBootState)
        } catch (_: Exception) {
            Parsed(0, null, null)
        }
    }

    private fun readBoolean(value: ByteArray): Boolean = value.isNotEmpty() && value[0].toInt() != 0
}
