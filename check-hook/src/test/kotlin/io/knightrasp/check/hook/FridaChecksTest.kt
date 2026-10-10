package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FridaChecksTest {

    @Test
    fun threads_clean_on_normal_process() {
        val probes = TestProbes()
        probes.proc.threads = listOf("main", "RenderThread", "Jit thread pool")
        assertEquals(CheckResult.Clean, FridaThreadsCheck(probes.proc).run(testContext(probes)))
    }

    @Test
    fun threads_detected_on_frida_agent() {
        val probes = TestProbes()
        probes.proc.threads = listOf("main", "gum-js-loop", "gmain")
        val result = FridaThreadsCheck(probes.proc).run(testContext(probes))
        val detected = result as CheckResult.Detected
        assertEquals(2, detected.evidence.size)
    }

    @Test
    fun threads_unknown_when_unreadable() {
        val probes = TestProbes()
        probes.proc.threads = emptyList()
        assertTrue(FridaThreadsCheck(probes.proc).run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun maps_clean_on_normal_process() {
        val probes = TestProbes()
        probes.proc.maps = "7f0000000000-7f0000001000 r-xp 00000000 08:01 1 /system/lib64/libc.so\n"
        assertEquals(CheckResult.Clean, FridaMapsCheck(probes.proc).run(testContext(probes)))
    }

    @Test
    fun maps_detected_on_frida_agent() {
        val probes = TestProbes()
        probes.proc.maps = """
            7f0000000000-7f0000001000 r-xp 00000000 08:01 1 /system/lib64/libc.so
            7f1000000000-7f1000100000 r-xp 00000000 00:00 0 /data/local/tmp/frida-agent.so
        """.trimIndent()
        val result = FridaMapsCheck(probes.proc).run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }

    @Test
    fun maps_unknown_when_unreadable() {
        val probes = TestProbes()
        probes.proc.maps = null
        assertTrue(FridaMapsCheck(probes.proc).run(testContext(probes)) is CheckResult.Unknown)
    }
}
