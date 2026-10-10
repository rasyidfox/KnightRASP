package io.knightrasp.nativebridge

import io.knightrasp.probe.NativeProbe

/**
 * Implementasi [NativeProbe] di atas library native SDK.
 *
 * Nama file library berasal dari `BuildConfig.NATIVE_LIB_NAME` (diatur lewat properti
 * Gradle `rasp.nativeLibName`) sehingga output `.so` tidak memuat kata "rasp".
 *
 * Jika library tidak dapat dimuat (ABI tidak didukung, .so hilang), [createOrNull]
 * mengembalikan null dan check yang bergantung pada native melaporkan Unknown —
 * SDK tetap berjalan (fail-open). Pemuatan senyap: tidak ada log.
 *
 * Nama kelas dan method `external` adalah kontrak dengan sisi C++ (JNI), jangan diubah
 * tanpa mengubah `knightrasp.cpp`. Modul `rasp` sudah menyertakan ProGuard rule agar nama
 * ini tidak di-obfuscate.
 */
class NativeProbeImpl private constructor() : NativeProbe {

    override val libraryFileName: String = "lib${BuildConfig.NATIVE_LIB_NAME}.so"

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
        private val available: Boolean = try {
            System.loadLibrary(BuildConfig.NATIVE_LIB_NAME)
            true
        } catch (_: Throwable) {
            false
        }

        /** Probe native, atau null bila library tidak tersedia pada build/ABI ini. */
        @JvmStatic
        fun createOrNull(): NativeProbe? = if (available) NativeProbeImpl() else null
    }
}
