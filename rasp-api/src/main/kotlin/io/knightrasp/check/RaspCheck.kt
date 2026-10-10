package io.knightrasp.check

import io.knightrasp.model.Category
import io.knightrasp.model.Evidence

/**
 * Satu unit deteksi. Implementasi harus:
 *
 * - hanya mengakses OS lewat [RaspContext.probes] (agar dapat di-unit-test);
 * - tidak memblokir lebih lama dari timeout yang wajar — mesin akan memutus check;
 * - mengembalikan [CheckResult.Unknown] bila probe gagal, bukan melempar exception.
 */
interface RaspCheck {
    /** Id stabil, dipakai untuk konfigurasi dan whitelist, mis. `root.su_binary`. */
    val id: String

    val category: Category

    /** Menentukan urutan eksekusi (LOW lebih dulu) dan timeout default. */
    val cost: Cost

    fun run(ctx: RaspContext): CheckResult
}

enum class Cost { LOW, MEDIUM, HIGH }

sealed interface CheckResult {
    /** Tidak ada indikasi. */
    data object Clean : CheckResult

    /** Terdeteksi; bawa satu atau lebih evidence. */
    data class Detected(val evidence: List<Evidence>) : CheckResult

    /** Tidak dapat disimpulkan (probe gagal / tidak didukung). Tidak menambah skor. */
    data class Unknown(val reason: String) : CheckResult
}
