package io.knightrasp.probe.android

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import io.knightrasp.probe.PackageProbe
import java.security.MessageDigest

class AndroidPackageProbe(private val context: Context) : PackageProbe {

    override fun isInstalled(packageName: String): Boolean = try {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    } catch (_: Exception) {
        false
    }

    override fun signingCertSha256(packageName: String): List<String> {
        return try {
            val pm = context.packageManager
            val certs: List<Signature> = if (Build.VERSION.SDK_INT >= 28) {
                val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = info.signingInfo ?: return emptyList()
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners.toList()
                } else {
                    signingInfo.signingCertificateHistory.toList()
                }
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures?.toList()
                    ?: emptyList()
            }
            certs.mapNotNull { sha256Hex(it.toByteArray()) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    override fun installerPackageName(packageName: String): String? {
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= 30) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }
    }

    override fun apkPath(packageName: String): String? = try {
        context.packageManager.getApplicationInfo(packageName, 0).sourceDir
    } catch (_: Exception) {
        null
    }

    private fun sha256Hex(bytes: ByteArray): String? = try {
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString(separator = "") { "%02x".format(it) }
    } catch (_: Exception) {
        null
    }
}
