package io.knightrasp.check.integrity

import io.knightrasp.check.CheckResult
import io.knightrasp.testing.TestNativeProbe
import io.knightrasp.testing.TestProbes
import io.knightrasp.testing.testContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SdkLibraryOriginCheckTest {

    private val apkPath = "/data/app/~~x123/io.knightrasp.test-y456/base.apk"
    private val packageName = "io.knightrasp.test"

    private fun probes(
        withNative: Boolean = true,
        maps: String? = null,
        apkPathValue: String? = apkPath,
    ): TestProbes {
        val probes = TestProbes(native = if (withNative) TestNativeProbe() else null)
        apkPathValue?.let { probes.packages.apkPaths[packageName] = it }
        maps?.let { probes.proc.maps = it }
        return probes
    }

    @Test
    fun unknown_without_native_probe() {
        val probes = probes(withNative = false, maps = "")
        assertTrue(SdkLibraryOriginCheck(probes.proc, probes.packages, probes.native)
            .run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun unknown_without_apk_path() {
        val probes = probes(maps = "", apkPathValue = null)
        assertTrue(SdkLibraryOriginCheck(probes.proc, probes.packages, probes.native)
            .run(testContext(probes)) is CheckResult.Unknown)
    }

    @Test
    fun clean_when_library_loaded_from_apk() {
        val probes = probes(
            maps = "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 " +
                "$apkPath!/lib/arm64-v8a/libguardcore.so\n",
        )
        val result = SdkLibraryOriginCheck(probes.proc, probes.packages, probes.native)
            .run(testContext(probes))
        assertEquals(CheckResult.Clean, result)
    }

    @Test
    fun clean_when_library_loaded_from_split_apk() {
        val probes = probes(
            maps = "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 " +
                "/data/app/~~x123/io.knightrasp.test-y456/split_config.arm64_v8a.apk" +
                "!/lib/arm64-v8a/libguardcore.so\n",
        )
        val result = SdkLibraryOriginCheck(probes.proc, probes.packages, probes.native)
            .run(testContext(probes))
        assertEquals(CheckResult.Clean, result)
    }

    @Test
    fun detected_when_library_loaded_from_outside_apk() {
        val probes = probes(
            maps = "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 " +
                "/data/local/tmp/libguardcore.so\n",
        )
        val result = SdkLibraryOriginCheck(probes.proc, probes.packages, probes.native)
            .run(testContext(probes))
        assertEquals(CheckResult.Detected::class.java, result.javaClass)
    }

    @Test
    fun unknown_when_library_missing_from_maps() {
        val probes = probes(maps = "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 /system/lib64/libc.so\n")
        assertTrue(SdkLibraryOriginCheck(probes.proc, probes.packages, probes.native)
            .run(testContext(probes)) is CheckResult.Unknown)
    }
}
