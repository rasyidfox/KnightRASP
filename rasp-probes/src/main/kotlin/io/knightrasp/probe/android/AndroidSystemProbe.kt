package io.knightrasp.probe.android

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.os.Build
import android.os.Debug
import android.view.accessibility.AccessibilityManager
import io.knightrasp.probe.SystemProbe

class AndroidSystemProbe(private val context: Context) : SystemProbe {

    override val manufacturer: String get() = Build.MANUFACTURER
    override val brand: String get() = Build.BRAND
    override val model: String get() = Build.MODEL
    override val device: String get() = Build.DEVICE
    override val product: String get() = Build.PRODUCT
    override val hardware: String get() = Build.HARDWARE
    override val fingerprint: String get() = Build.FINGERPRINT
    override val tags: String get() = Build.TAGS
    override val supportedAbis: List<String> get() = Build.SUPPORTED_ABIS.toList()
    override val sdkInt: Int get() = Build.VERSION.SDK_INT

    override fun isDebuggerConnected(): Boolean = Debug.isDebuggerConnected()

    override fun enabledAccessibilityServiceIds(): List<String> = try {
        val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
        manager?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            ?.mapNotNull { info ->
                val serviceInfo = info.resolveInfo?.serviceInfo ?: return@mapNotNull null
                "${serviceInfo.packageName}/${serviceInfo.name}"
            }
            ?: emptyList()
    } catch (_: Exception) {
        emptyList()
    }
}
