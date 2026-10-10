package io.knightrasp.util

import android.os.Build
import android.view.MotionEvent

/**
 * Utilitas untuk memeriksa tapjacking pada touch event.
 *
 * RASP tidak bisa "mendeteksi overlay" dari luar; yang benar adalah memeriksa flag
 * pada setiap touch event yang masuk ke aplikasi. Panggil [isObscured] di
 * `onTouchEvent`/`dispatchTouchEvent` dan tolak aksi sensitif bila true, atau pasang
 * `android:filterTouchesWhenObscured="true"` pada view penting.
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
