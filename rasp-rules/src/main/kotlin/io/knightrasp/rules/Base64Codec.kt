package io.knightrasp.rules

import java.io.ByteArrayOutputStream

/**
 * Standard Base64 (RFC 4648) with no dependencies.
 *
 * Does not use `android.util.Base64` so this module can be unit-tested purely on the JVM,
 * and does not use `java.util.Base64`, which is only available since API 26.
 */
internal object Base64Codec {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    private val DECODE_TABLE = IntArray(128) { -1 }.also { table ->
        ALPHABET.forEachIndexed { index, char -> table[char.code] = index }
    }

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size + 2) / 3 * 4)
        var index = 0
        while (index < bytes.size) {
            val b0 = bytes[index].toInt() and 0xFF
            val b1 = if (index + 1 < bytes.size) bytes[index + 1].toInt() and 0xFF else 0
            val b2 = if (index + 2 < bytes.size) bytes[index + 2].toInt() and 0xFF else 0
            val chunk = (b0 shl 16) or (b1 shl 8) or b2

            out.append(ALPHABET[chunk ushr 18 and 0x3F])
            out.append(ALPHABET[chunk ushr 12 and 0x3F])
            out.append(if (index + 1 < bytes.size) ALPHABET[chunk ushr 6 and 0x3F] else '=')
            out.append(if (index + 2 < bytes.size) ALPHABET[chunk and 0x3F] else '=')
            index += 3
        }
        return out.toString()
    }

    fun decode(text: String): ByteArray {
        val out = ByteArrayOutputStream(text.length * 3 / 4 + 3)
        var buffer = 0
        var bits = 0
        for (char in text) {
            if (char == '=' || char.isWhitespace()) {
                continue
            }
            require(char.code < DECODE_TABLE.size && DECODE_TABLE[char.code] >= 0) {
                "Invalid Base64 character"
            }
            buffer = (buffer shl 6) or DECODE_TABLE[char.code]
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write(buffer ushr bits and 0xFF)
            }
        }
        return out.toByteArray()
    }
}
