package io.knightrasp.core

import android.util.Log

/**
 * Internal logger — **debug** variant.
 *
 * Active only when `RaspConfig.debugLogging = true`. All call sites are wrapped in
 * `if (RaspLog.ENABLED)` so R8 can remove all logging (including the message
 * strings) in release builds.
 */
object RaspLog {

    /** Compile-time constant; `true` in the debug variant. */
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
