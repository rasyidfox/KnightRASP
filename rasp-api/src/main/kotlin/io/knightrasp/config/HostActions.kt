package io.knightrasp.config

import io.knightrasp.model.ThreatAssessment

/**
 * Hook aksi tingkat aplikasi yang tidak bisa dilakukan SDK sendirian.
 *
 * Implementasi dipanggil di main thread oleh executor response. Pada [Mode.MONITOR]
 * seluruh aksi di sini dilewati sehingga SDK aman dipasang di produksi untuk mengukur
 * false positive terlebih dahulu.
 */
interface HostActions {
    /** Matikan fitur sensitif untuk sementara (mis. transfer besar, biometrik). */
    fun degrade(assessment: ThreatAssessment) {}

    /** Bersihkan token/session dan paksa pengguna login ulang. */
    fun logout(assessment: ThreatAssessment) {}

    /** Blokir operasi sensitif berikutnya sampai review. */
    fun blockSensitiveOps(assessment: ThreatAssessment) {}

    companion object {
        /** Implementasi kosong untuk aplikasi yang belum menyiapkan aksi lanjutan. */
        @JvmField
        val NONE: HostActions = object : HostActions {}
    }
}
