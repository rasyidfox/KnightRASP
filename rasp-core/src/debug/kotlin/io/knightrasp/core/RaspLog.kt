package io.knightrasp.core

import android.util.Log

/**
 * Logger internal — varian **debug**.
 *
 * Aktif hanya bila `RaspConfig.debugLogging = true`. Semua call site dibungkus
 * `if (RaspLog.ENABLED)` supaya R8 dapat menghapus seluruh logging (termasuk string
 * pesan) pada varian release.
 */
object RaspLog {

    /** Konstanta compile-time; `true` pada varian debug. */
    const val ENABLED: Boolean = true

    private const val TAG = "KnightRASP"

    @Volatile
    private var runtimeEnabled = false

    fun setEnabled(enabled: Boolean) {
        runtimeEnabled = enabled
    }

    fun d(message: String) {
        if (runtimeEnabled) {
            Log.d(TAG, message)
        }
    }

    fun w(message: String, cause: Throwable? = null) {
        if (runtimeEnabled) {
            Log.w(TAG, message, cause)
        }
    }

    fun e(message: String, cause: Throwable? = null) {
        if (runtimeEnabled) {
            Log.e(TAG, message, cause)
        }
    }
}
