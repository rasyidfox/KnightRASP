package io.knightrasp.core

/**
 * Logger internal — varian **release**: no-op.
 *
 * `ENABLED` adalah konstanta `false`, sehingga R8 menghapus seluruh call site logging
 * beserta string pesannya. Tidak ada referensi ke `android.util.Log` di APK release.
 */
object RaspLog {

    const val ENABLED: Boolean = false

    fun setEnabled(enabled: Boolean) = Unit

    fun d(message: String) = Unit

    fun w(message: String, cause: Throwable? = null) = Unit

    fun e(message: String, cause: Throwable? = null) = Unit
}
