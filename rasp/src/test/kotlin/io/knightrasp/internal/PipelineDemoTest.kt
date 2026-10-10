package io.knightrasp.internal

import io.knightrasp.config.Policy
import io.knightrasp.config.RaspConfig
import io.knightrasp.config.Response
import io.knightrasp.core.ScanEngine
import io.knightrasp.core.Scorer
import io.knightrasp.core.TtlCache
import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.testing.TestNativeProbe
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Demo end-to-end pipeline RASP di JVM (tanpa device): 21 check asli + engine dua
 * gelombang + scorer noisy-OR + simulasi policy. Probe diganti fake.
 */
class PipelineDemoTest {

    private val packageName = "io.knightrasp.test"

    private val config = RaspConfig(
        expectedSignatureSha256 = setOf("aabb"),
        allowedInstallers = setOf("com.android.vending"),
        allowedAccessibilityServices = setOf("com.google.android.marvin.talkback/.TalkBackService"),
    )

    private val policy = Policy { assessment ->
        when {
            assessment.level >= Level.CRITICAL -> listOf(Response.Exit, Response.Report)
            assessment.level >= Level.HIGH -> listOf(Response.Logout, Response.Report)
            assessment.level >= Level.MEDIUM -> listOf(Response.Degrade, Response.Report)
            assessment.level >= Level.LOW -> listOf(Response.Report)
            else -> listOf(Response.Log)
        }
    }

    @Test
    fun clean_device_is_reported_as_none() {
        val assessment = scan(cleanProbes())

        report("Perangkat bersih (probe default)", assessment)

        assertEquals(Level.NONE, assessment.level)
        assertEquals(0, assessment.evidence.size)
    }

    @Test
    fun compromised_device_is_reported_as_critical() {
        val assessment = scan(compromisedProbes())

        report("Perangkat terkompromi (root + hook + tamper + cloner)", assessment)

        assertEquals(Level.CRITICAL, assessment.level)
        assertTrue("kategori terdeteksi: ${assessment.categories.size}", assessment.categories.size >= 6)
    }

    private fun scan(probes: TestProbes): ThreatAssessment = runBlocking {
        val engine = ScanEngine(
            checks = DefaultChecks.list(probes),
            scorer = Scorer(config.thresholds),
            cache = TtlCache(),
            workScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
        )
        engine.scan(testContext(probes, config, packageName = packageName), useCache = false)
    }

    private fun cleanProbes(): TestProbes = TestProbes().apply {
        packages.signingCerts[packageName] = listOf("aabb")
        packages.installers[packageName] = "com.android.vending"
        packages.apkPaths[packageName] = "/data/app/base.apk"
        proc.status = "Name:\t$packageName\nTracerPid:\t0\n"
        proc.maps = "7f00-7f01 r-xp 00000000 00:00 0 " +
            "/data/app/base.apk!/lib/arm64-v8a/libguardcore.so\n"
        proc.cmdline = packageName
        proc.threads = listOf("main", "RenderThread")
    }

    private fun compromisedProbes(): TestProbes {
        val native = TestNativeProbe().apply {
            hooked = true
            textModified = true
            debuggerDetected = true
        }
        return TestProbes(native = native).apply {
            file.add("/system/xbin/su")
            file.add("/data/adb/magisk")
            file.add("/data/adb/modules")
            packages.installed += "com.topjohnwu.magisk"
            packages.installed += "com.lbe.parallel"
            packages.signingCerts[packageName] = listOf("deadbeef")
            packages.apkPaths[packageName] = "/data/app/base.apk"

            settings.global["adb_enabled"] = 1
            settings.global["development_settings_enabled"] = 1
            settings.secure["mock_location"] = 1

            system.tags = "test-keys"
            system.debuggerConnected = true
            system.manufacturer = "Google"
            system.model = "sdk_gphone64_x86_64"
            system.hardware = "ranchu"
            system.product = "sdk_gphone64_x86_64"
            system.fingerprint = "google/sdk_gphone64_x86_64/emulator64_x86_64:14/UP1A:user/dev-keys"
            system.supportedAbis = listOf("x86_64", "arm64-v8a")
            system.accessibilityServices = listOf("com.suspicious.aid/com.suspicious.aid.Service")

            proc.status = "Name:\t$packageName\nTracerPid:\t4242\n"
            proc.maps = "7f10-7f20 r-xp 00000000 00:00 0 /data/local/tmp/frida-agent.so\n" +
                "7f30-7f40 r-xp 00000000 00:00 0 /data/local/tmp/libguardcore.so\n"
            proc.threads = listOf("main", "gum-js-loop", "gmain")
            proc.cmdline = "com.lbe.parallel:vPlayer"
        }
    }

    private fun report(title: String, assessment: ThreatAssessment) {
        val requested = policy.responsesFor(assessment).joinToString { it.toString() }
        val categories = assessment.categories.entries
            .sortedByDescending { it.value }
            .joinToString { "${it.key}=${format(it.value)}" }

        println()
        println("=".repeat(78))
        println("SKENARIO : $title")
        println("CHECK    : $checkCount check dieksekusi")
        println("LEVEL    : ${assessment.level}  (score ${format(assessment.score)})")
        println("KATEGORI : $categories")
        println("EVIDENCE (${assessment.evidence.size}):")
        assessment.evidence.sortedByDescending { it.confidence }.forEach {
            println("   - ${it.ruleId} [${format(it.confidence)}] ${it.detail ?: ""}")
        }
        println("POLICY   : $requested")
        println("=".repeat(78))
    }

    private fun format(value: Float): String = "%.2f".format(value)

    private companion object {
        val checkCount: Int by lazy { DefaultChecks.list(TestProbes()).size }
    }
}
