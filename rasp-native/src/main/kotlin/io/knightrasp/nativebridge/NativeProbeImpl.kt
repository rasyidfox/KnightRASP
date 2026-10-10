package io.knightrasp.nativebridge

import io.knightrasp.probe.NativeProbe
import io.knightrasp.util.ObfuscatedStrings

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
class NativeProbeImpl private constructor() : NativeProbe {

    override val libraryFileName: String = "lib${decodedLibraryName()}.so"

    override fun isDebuggerDetected(): Boolean = nativeAntiDebug()

    override fun isHooked(): Boolean = nativeAntiHook()

    override fun isTextModified(): Boolean = nativeTextIntegrity()

    override fun killProcess() {
        nativeKillProcess()
    }

    private external fun nativeAntiDebug(): Boolean

    private external fun nativeAntiHook(): Boolean

    private external fun nativeTextIntegrity(): Boolean

    private external fun nativeKillProcess()

    companion object {
        private fun decodedLibraryName(): String =
            ObfuscatedStrings.decode(
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
        fun createOrNull(): NativeProbe? = if (available) NativeProbeImpl() else null
    }
}
