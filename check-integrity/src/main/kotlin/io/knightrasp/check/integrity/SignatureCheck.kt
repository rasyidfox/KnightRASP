package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.PackageProbe

/**
 * Compares the SHA-256 of the running APK signing certificate against the list
 * expected from [RaspContext.config]. An app repacked with another key will be
 * detected.
 *
 * When `expectedSignatureSha256` is empty, the check reports Unknown (no verification).
 * For apps with Play App Signing, use the Play signing certificate
 * (not the upload key) and also include the old certificate if key rotation is active.
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
            return CheckResult.Unknown("expectedSignatureSha256 not configured")
        }

        val actual = packages.signingCertSha256(ctx.packageName).map { it.lowercase() }
        if (actual.isEmpty()) {
            return CheckResult.Unknown("signing certificate unreadable")
        }

        return if (actual.any { it in expected }) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(
                listOf(Evidence(id, CONFIDENCE, "APK signature does not match the expected value"))
            )
        }
    }

    companion object {
        const val CONFIDENCE = 0.95f
    }
}
