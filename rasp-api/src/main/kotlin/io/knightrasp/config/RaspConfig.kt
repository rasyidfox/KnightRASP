package io.knightrasp.config

import io.knightrasp.model.ThreatAssessment
import io.knightrasp.telemetry.TelemetrySink

/**
 * Konfigurasi SDK.
 *
 * @param mode MONITOR: response berbahaya (Exit, Degrade, Logout, BlockSensitiveOps)
 *   tidak dieksekusi; PROTECT: dieksekusi penuh.
 * @param environment QA mematikan blokir untuk perangkat pengembangan (versi berikutnya
 *   menambahkan allowlist emulator/perangkat tim).
 * @param enabledChecks daftar `checkId` yang diaktifkan; kosong berarti semua.
 * @param disabledChecks daftar `checkId` yang dimatikan; menang atas [enabledChecks].
 * @param thresholds ambang skor untuk pemetaan [io.knightrasp.model.Level].
 * @param policy fungsi yang memetakan assessment ke daftar [Response].
 * @param telemetry sink telemetry; default tidak mengirim apa pun.
 * @param multiProcess MAIN_ONLY: hanya proses utama menjalankan mesin RASP.
 * @param expectedSignatureSha256 SHA-256 (hex, lowercase) sertifikat penandatangan yang
 *   sah. Bila kosong, `integrity.signature` melaporkan Unknown (tidak memverifikasi).
 * @param allowedInstallers paket installer yang dianggap sah (mis.
 *   `com.android.vending`). Bila kosong, `integrity.installer` melaporkan Unknown.
 * @param hostActions implementasi aksi tingkat aplikasi; default tidak melakukan apa pun.
 * @param rules tuning dari remote rules yang sudah diverifikasi; null berarti tanpa rules.
 * @param allowedAccessibilityServices id layanan accessibility (`paket/kelas`) yang
 *   dianggap sah (mis. TalkBack). Bila kosong, `env.accessibility_services` melaporkan
 *   Unknown agar tidak menuduh terlalu dini.
 * @param debugLogging menyalakan log internal SDK. Default `false` (senyap) — pada
 *   build release, kode logging tidak ada sama sekali.
 */
data class RaspConfig @JvmOverloads constructor(
    val mode: Mode = Mode.MONITOR,
    val environment: Environment = Environment.RELEASE,
    val enabledChecks: Set<String> = emptySet(),
    val disabledChecks: Set<String> = emptySet(),
    val thresholds: Thresholds = Thresholds(),
    val policy: Policy = Policy.ALERT_ONLY,
    val telemetry: TelemetrySink = TelemetrySink.NOOP,
    val multiProcess: MultiProcessMode = MultiProcessMode.MAIN_ONLY,
    val expectedSignatureSha256: Set<String> = emptySet(),
    val allowedInstallers: Set<String> = emptySet(),
    val hostActions: HostActions = HostActions.NONE,
    val rules: RaspRules? = null,
    val allowedAccessibilityServices: Set<String> = emptySet(),
    val debugLogging: Boolean = false,
)

enum class Mode { MONITOR, PROTECT }

enum class Environment { RELEASE, QA }

enum class MultiProcessMode { MAIN_ONLY, ALL }

/**
 * Ambang skor (0..1). Pemetaan standar:
 * `score >= high` → CRITICAL, `>= medium` → HIGH, `>= low` → MEDIUM, `> 0` → LOW.
 */
data class Thresholds(
    val low: Float = 0.30f,
    val medium: Float = 0.60f,
    val high: Float = 0.85f,
)

/** Kebijakan milik aplikasi: assessment → response yang diminta. */
fun interface Policy {
    fun responsesFor(assessment: ThreatAssessment): List<Response>

    companion object {
        /** Default: log dan laporkan, tanpa aksi yang mengganggu pengguna. */
        @JvmField
        val ALERT_ONLY: Policy = Policy { listOf(Response.Log, Response.Report) }
    }
}

/**
 * Aksi yang diminta oleh [Policy].
 *
 * Response `Exit`, `Degrade`, `Logout`, dan `BlockSensitiveOps` hanya dieksekusi pada
 * [Mode.PROTECT]; pada [Mode.MONITOR] semuanya dilewati (hanya dicatat di log).
 */
sealed interface Response {
    /** Tulis ringkasan assessment ke logcat. */
    data object Log : Response

    /** Kirim assessment ke [TelemetrySink] yang dikonfigurasi. */
    data object Report : Response

    /** Hentikan proses aplikasi (native syscall bila tersedia). */
    data object Exit : Response

    /** Minta host menonaktifkan fitur sensitif sementara lewat [HostActions.degrade]. */
    data object Degrade : Response

    /** Minta host membersihkan session dan memaksa login ulang lewat [HostActions.logout]. */
    data object Logout : Response

    /** Minta host memblokir operasi sensitif lewat [HostActions.blockSensitiveOps]. */
    data object BlockSensitiveOps : Response

    /** Aksi milik aplikasi; dipanggil di main thread. */
    data class Custom(val action: () -> Unit) : Response
}
