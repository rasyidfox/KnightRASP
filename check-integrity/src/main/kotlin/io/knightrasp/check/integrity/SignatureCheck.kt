package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.PackageProbe

/**
 * Membandingkan SHA-256 sertifikat penandatangan APK yang berjalan dengan daftar yang
 * diharapkan dari [RaspContext.config]. Aplikasi yang di-repack dengan kunci lain akan
 * terdeteksi.
 *
 * Bila `expectedSignatureSha256` kosong, check melaporkan Unknown (tidak memverifikasi).
 * Untuk aplikasi dengan Play App Signing, gunakan sertifikat penandatanganan Play
 * (bukan upload key) dan sertakan juga sertifikat lama bila rotasi kunci aktif.
 */
class SignatureCheck(private val packages: PackageProbe) : RaspCheck {

    override val id = "integrity.signature"
    override val category = Category.INTEGRITY
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val expected = ctx.config.expectedSignatureSha256
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() }
            .toSet()
        if (expected.isEmpty()) {
            return CheckResult.Unknown("expectedSignatureSha256 belum dikonfigurasi")
        }

        val actual = packages.signingCertSha256(ctx.packageName).map { it.lowercase() }
        if (actual.isEmpty()) {
            return CheckResult.Unknown("sertifikat penandatangan tidak terbaca")
        }

        return if (actual.any { it in expected }) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "signature APK tidak cocok dengan yang diharapkan"))
            )
        }
    }

    companion object {
        const val CONFIDENCE = 0.95f
    }
}
