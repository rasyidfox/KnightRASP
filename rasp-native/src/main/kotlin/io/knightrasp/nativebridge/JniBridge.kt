package io.knightrasp.nativebridge

import io.knightrasp.probe.NativeProbe
import io.knightrasp.util.TextCodec

/**
 * [NativeProbe] implementation backed by the SDK's native library.
 *
 * The library name is decoded at runtime from an obfuscated BuildConfig value
 * (configured through the `knightrasp.nativeLibName` Gradle property), so the
 * plain name does not appear as a literal in the dex.
 *
 * If the library cannot be loaded (unsupported ABI, missing .so), [createOrNull]
 * returns null and native-dependent checks report Unknown — the SDK stays
 * fail-open. Loading is silent: no logging.
 *
 * Class and `external` method names are part of the C++ (JNI) contract: the
 * native side binds them with RegisterNatives in JNI_OnLoad. Do not rename them
 * without updating `knightrasp.cpp`; the `rasp` module ships a ProGuard rule to
 * keep this class intact.
 */
class JniBridge private constructor() : NativeProbe {

    override val moduleName: String = "lib${decodedLibraryName()}.so"

    override fun signalA(): Boolean = n1()

    override fun signalB(): Boolean = n2()

    override fun signalC(): Boolean = n3()

    override fun signalD(): Boolean = n5()

    override fun signalE(): Boolean = n6()

    override fun signalF(): Boolean = n7()

    override fun signalG(): Boolean = n10()

    override fun signalH(): Boolean = n11()

    override fun watchdog(enabled: Boolean, killOnEvidence: Boolean, intervalMs: Int) {
        n8(enabled, killOnEvidence, intervalMs)
    }

    override fun signalRisk(detected: Boolean) {
        n9(detected)
    }

    override fun shutdown() {
        n4()
    }

    private external fun n1(): Boolean

    private external fun n2(): Boolean

    private external fun n3(): Boolean

    private external fun n4()

    private external fun n5(): Boolean

    private external fun n6(): Boolean

    private external fun n7(): Boolean

    private external fun n8(enabled: Boolean, killOnEvidence: Boolean, intervalMs: Int)

    private external fun n9(detected: Boolean)

    private external fun n10(): Boolean

    private external fun n11(): Boolean

    companion object {
        private fun decodedLibraryName(): String =
            TextCodec.decode(
                BuildConfig.NATIVE_LIB_NAME_OBF,
                BuildConfig.NATIVE_LIB_NAME_KEY,
            )

        private val available: Boolean = try {
            System.loadLibrary(decodedLibraryName())
            true
        } catch (_: Throwable) {
            false
        }

        /** Native probe, or null when the library is unavailable on this build/ABI. */
        @JvmStatic
        fun createOrNull(): NativeProbe? = if (available) JniBridge() else null
    }
}
