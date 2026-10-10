package io.knightrasp.check.environment

import io.knightrasp.check.CheckResult
import io.knightrasp.config.RaspConfig
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AccessibilityServicesCheckTest {

    @Test
    fun unknown_when_allowlist_not_configured() {
        val probes = TestProbes()
        probes.system.accessibilityServices = listOf("com.example.aid/com.example.aid.Service")
        assertTrue(AccessibilityServicesCheck(probes.system).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun clean_when_no_service_enabled() {
        val probes = TestProbes()
        val config = RaspConfig(allowedAccessibilityServices = setOf("com.google.android.marvin.talkback/.TalkBackService"))
        assertEquals(
            CheckResult.Clean,
            AccessibilityServicesCheck(probes.system).run(testContext(probes, config)),
        )
    }

    @Test
    fun clean_when_all_enabled_services_allowed() {
        val probes = TestProbes()
        probes.system.accessibilityServices = listOf("com.google.android.marvin.talkback/.TalkBackService")
        val config = RaspConfig(allowedAccessibilityServices = setOf("com.google.android.marvin.talkback/.TalkBackService"))
        assertEquals(
            CheckResult.Clean,
            AccessibilityServicesCheck(probes.system).run(testContext(probes, config)),
        )
    }

    @Test
    fun detected_when_unknown_service_enabled() {
        val probes = TestProbes()
        probes.system.accessibilityServices = listOf(
            "com.google.android.marvin.talkback/.TalkBackService",
            "com.suspicious.aid/com.suspicious.aid.Service",
        )
        val config = RaspConfig(allowedAccessibilityServices = setOf("com.google.android.marvin.talkback/.TalkBackService"))
        val result = AccessibilityServicesCheck(probes.system).run(testContext(probes, config))
        val detected = result as CheckResult.Detected
        assertEquals(1, detected.evidence.size)
        assertTrue(detected.evidence.single().detail!!.contains("com.suspicious.aid"))
    }
}
