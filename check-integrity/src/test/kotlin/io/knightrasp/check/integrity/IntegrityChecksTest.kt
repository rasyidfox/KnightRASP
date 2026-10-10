package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.config.RaspConfig
import io.knightrasp.testing.TestNativeProbe
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IntegrityChecksTest {

    private val appPackage = "io.knightrasp.test"

    // --- integrity.signature ---

    @Test
    fun signature_unknown_when_not_configured() {
        val probes = TestProbes()
        assertTrue(SignatureCheck(probes.packages).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun signature_clean_when_matching() {
        val probes = TestProbes()
        probes.packages.signingCerts[appPackage] = listOf("aa11")
        val config = RaspConfig(expectedSignatureSha256 = setOf("AA11"))
        val result = SignatureCheck(probes.packages).run(testContext(probes, config))
        assertEquals(CheckResult.Clean, result)
    }

    @Test
    fun signature_detected_when_mismatch() {
        val probes = TestProbes()
        probes.packages.signingCerts[appPackage] = listOf("bb22")
        val config = RaspConfig(expectedSignatureSha256 = setOf("aa11"))
        val result = SignatureCheck(probes.packages).run(testContext(probes, config))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }

    // --- integrity.installer ---

    @Test
    fun installer_unknown_when_not_configured() {
        val probes = TestProbes()
        assertTrue(InstallerCheck(probes.packages).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun installer_clean_when_allowed() {
        val probes = TestProbes()
        probes.packages.installers[appPackage] = "com.android.vending"
        val config = RaspConfig(allowedInstallers = setOf("com.android.vending"))
        assertEquals(CheckResult.Clean, InstallerCheck(probes.packages).run(testContext(probes, config)))
    }

    @Test
    fun installer_detected_for_sideload() {
        val probes = TestProbes()
        val config = RaspConfig(allowedInstallers = setOf("com.android.vending"))
        assertEquals(
            CheckResult.Detected::class.java,
            InstallerCheck(probes.packages).run(testContext(probes, config)).javaClass,
        )
    }

    @Test
    fun installer_detected_for_unknown_installer() {
        val probes = TestProbes()
        probes.packages.installers[appPackage] = "com.unknown.store"
        val config = RaspConfig(allowedInstallers = setOf("com.android.vending"))
        assertEquals(
            CheckResult.Detected::class.java,
            InstallerCheck(probes.packages).run(testContext(probes, config)).javaClass,
        )
    }

    // --- integrity.native_text ---

    @Test
    fun native_text_unknown_without_native() {
        val probes = TestProbes(native = null)
        assertTrue(NativeTextIntegrityCheck(probes.native).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun native_text_clean_by_default() {
        val probes = TestProbes()
        assertEquals(CheckResult.Clean, NativeTextIntegrityCheck(probes.native).run(testContext(probes)))
    }

    @Test
    fun native_text_detected_when_modified() {
        val native = TestNativeProbe().apply { textModified = true }
        val probes = TestProbes(native = native)
        assertEquals(
            CheckResult.Detected::class.java,
            NativeTextIntegrityCheck(probes.native).run(testContext(probes)).javaClass,
        )
    }
}
