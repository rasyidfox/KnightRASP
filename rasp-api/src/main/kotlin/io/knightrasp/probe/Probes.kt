package io.knightrasp.probe

/**
 * Kumpulan probe — satu-satunya jalur check untuk mengakses OS.
 * Implementasi produksi ada di modul `rasp-probes`; test memakai fake.
 */
interface Probes {
    val file: FileProbe
    val proc: ProcProbe
    val packages: PackageProbe
    val settings: SettingsProbe
    val system: SystemProbe

    /** Probe native; null bila library native tidak tersedia (mis. varian tanpa NDK). */
    val native: NativeProbe?
}

interface FileProbe {
    fun exists(path: String): Boolean

    /** Isi file sebagai UTF-8, atau null bila tidak bisa dibaca. */
    fun read(path: String): String?
}

interface ProcProbe {
    /** Isi /proc/self/status, atau null bila gagal. */
    fun selfStatus(): String?

    /** Isi /proc/self/maps, atau null bila gagal. */
    fun selfMaps(): String?

    /** Nama proses dari /proc/self/cmdline, atau null bila gagal. */
    fun selfCmdline(): String?

    /** Nama thread proses ini (dari /proc/self/task/&lt;tid&gt;/comm). */
    fun threadNames(): List<String>
}

interface PackageProbe {
    /**
     * Apakah paket terpasang dan terlihat oleh aplikasi.
     * Catatan: pada Android 11+ visibilitas dibatasi; modul check mendeklarasikan
     * `<queries>` untuk paket yang dicek.
     */
    fun isInstalled(packageName: String): Boolean

    /** SHA-256 (hex, lowercase) dari sertifikat penandatangan paket. */
    fun signingCertSha256(packageName: String): List<String>

    /** Paket installer (mis. com.android.vending), atau null bila di-sideload. */
    fun installerPackageName(packageName: String): String?

    /** Path APK terpasang (sourceDir) paket, atau null bila tidak terbaca. */
    fun apkPath(packageName: String): String?
}

interface SettingsProbe {
    fun globalInt(key: String, default: Int): Int

    fun secureInt(key: String, default: Int): Int
}

/** Properti perangkat & status runtime dasar. */
interface SystemProbe {
    val manufacturer: String
    val brand: String
    val model: String
    val device: String
    val product: String
    val hardware: String
    val fingerprint: String
    val tags: String
    val supportedAbis: List<String>
    val sdkInt: Int

    fun isDebuggerConnected(): Boolean

    /** Id komponen layanan accessibility yang aktif (format `paket/kelas`). */
    fun enabledAccessibilityServiceIds(): List<String>
}

/**
 * Probe yang berjalan di C/C++ lewat JNI. Dipakai untuk cek yang tidak dapat dipercaya
 * bila seluruhnya dijalankan di layer Java.
 */
interface NativeProbe {
    /**
     * Nama file library native yang sedang dimuat, mis. `libguardcore.so`.
     * Dipakai check anti-tamper untuk mengenali mapping milik SDK sendiri.
     */
    val libraryFileName: String

    /** true = indikasi proses sedang di-ptrace / di-debug, terlihat dari layer native. */
    fun isDebuggerDetected(): Boolean

    /** true = segmen executable library native berubah dari baseline (indikasi patching). */
    fun isTextModified(): Boolean

    /** true = artefak hook (frida/xposed/substrate) terlihat dari pembacaan /proc/self/maps. */
    fun isHooked(): Boolean

    /** Hentikan proses lewat syscall langsung, tanpa melewati wrapper Java/libc. */
    fun killProcess()
}
