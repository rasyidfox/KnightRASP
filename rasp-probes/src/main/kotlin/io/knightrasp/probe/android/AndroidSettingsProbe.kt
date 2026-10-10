package io.knightrasp.probe.android

import android.content.Context
import android.provider.Settings
import io.knightrasp.probe.SettingsProbe

class AndroidSettingsProbe(private val context: Context) : SettingsProbe {

    override fun globalInt(key: String, default: Int): Int = try {
        Settings.Global.getInt(context.contentResolver, key, default)
    } catch (_: Exception) {
        default
    }

    override fun secureInt(key: String, default: Int): Int = try {
        Settings.Secure.getInt(context.contentResolver, key, default)
    } catch (_: Exception) {
        default
    }
}
