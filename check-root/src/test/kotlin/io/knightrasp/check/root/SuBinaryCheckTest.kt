package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SuBinaryCheckTest {

    @Test
    fun clean_on_clean_device() {
        val probes = TestProbes()
        val result = SuBinaryCheck(probes.file).run(testContext(probes))
        assertEquals(CheckResult.Clean, result)
    }

    @Test
    fun detected_when_su_binary_present() {
        val probes = TestProbes()
        probes.file.add("/system/xbin/su")
        probes.file.add("/data/local/su")

        val result = SuBinaryCheck(probes.file).run(testContext(probes))

        val detected = result as CheckResult.Detected
        assertEquals(2, detected.evidence.size)
        assertTrue(detected.evidence.all { it.ruleId == "root.su_binary" })
    }
}
