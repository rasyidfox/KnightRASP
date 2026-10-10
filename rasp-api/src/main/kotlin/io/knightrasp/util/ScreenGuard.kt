package io.knightrasp.util

import android.app.Activity
import android.view.WindowManager

/**
 * FLAG_SECURE utility to prevent screenshots/screen recording on sensitive screens.
 *
 * This is the only reliable screen-capture defense on Android: detecting recording
 * by other apps is not available through public APIs.
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
