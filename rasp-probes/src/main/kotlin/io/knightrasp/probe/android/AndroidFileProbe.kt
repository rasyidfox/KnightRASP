package io.knightrasp.probe.android

import io.knightrasp.probe.FileProbe
import java.io.File

class AndroidFileProbe : FileProbe {

    override fun exists(path: String): Boolean = try {
        File(path).exists()
    } catch (_: SecurityException) {
        false
    } catch (_: Exception) {
        false
    }

    override fun read(path: String): String? = try {
        val file = File(path)
        when {
            !file.exists() -> null
            file.length() > MAX_BYTES -> null
            else -> file.readText(Charsets.UTF_8)
        }
    } catch (_: Exception) {
        null
    }

    private companion object {
        const val MAX_BYTES = 1_048_576L
    }
}
