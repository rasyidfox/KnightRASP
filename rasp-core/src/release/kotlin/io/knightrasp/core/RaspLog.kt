package io.knightrasp.core

/**
 * Internal logger — **release** variant: no-op.
 *
 * `ENABLED` is the constant `false`, so R8 removes all logging call sites
 * along with their message strings. There are no references to `android.util.Log` in a release APK.
 */
object RaspLog {

    const val ENABLED: Boolean = false

    fun setEnabled(enabled: Boolean) = Unit

    fun d(message: String) = Unit

    fun w(message: String, cause: Throwable? = null) = Unit

    fun e(message: String, cause: Throwable? = null) = Unit
}
