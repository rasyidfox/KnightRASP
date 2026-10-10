package io.knightrasp.util

/**
 * Minimal runtime string obfuscation used for detection-sensitive constants
 * (paths, markers, package names). Values are stored as hex-encoded XOR blobs
 * in the dex so plaintext markers do not appear in a static string dump.
 *
 * This is obfuscation, not cryptography: it raises the cost of static analysis,
 * it does not hide anything from a determined attacker (see README hardening
 * notes). Internal use only.
 */
object TextCodec {

    /** Decodes a hex string back to text using a single-byte XOR key. */
    @JvmStatic
    fun decode(hex: String, key: Int): String {
        require(hex.length % 2 == 0) { "Invalid encoded string" }
        val mask = key and 0xFF
        val out = CharArray(hex.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid encoded string" }
            out[i] = (((hi shl 4) or lo) xor mask).toChar()
        }
        return String(out)
    }

    /** Decodes a newline-joined list of obfuscated values. */
    @JvmStatic
    @JvmOverloads
    fun decodeList(hex: String, key: Int, separator: Char = '\n'): List<String> =
        decode(hex, key).split(separator)
}
