package io.knightrasp.util

import android.os.Build
import android.view.MotionEvent

/**
 * Utility for checking tapjacking on touch events.
 *
 * RASP cannot "detect overlays" from the outside; the right approach is to check the flag
 * on every touch event entering the app. Call [isObscured] in
 * `onTouchEvent`/`dispatchTouchEvent` and reject sensitive actions when true, or set
 * `android:filterTouchesWhenObscured="true"` on important views.
 */
object TouchSafety {

    @JvmStatic
    fun isObscured(event: MotionEvent): Boolean {
        val flags = event.flags
        if (flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0) {
            return true
        }
        return if (Build.VERSION.SDK_INT >= 31) {
            flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
        } else {
            false
        }
    }
}
