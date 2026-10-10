package io.knightrasp.util

import android.app.Activity
import android.view.WindowManager

/**
 * Utilitas FLAG_SECURE untuk mencegah screenshot/screen recording pada layar sensitif.
 *
 * Ini satu-satunya pertahanan screen capture yang andal di Android: deteksi perekaman
 * milik aplikasi lain tidak tersedia lewat API publik.
 */
object ScreenGuard {

    @JvmStatic
    fun enableSecure(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
    }

    @JvmStatic
    fun disableSecure(activity: Activity) {
        activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
