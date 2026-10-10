package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.ProcProbe

/**
 * Artefak framework hook (Frida/Xposed/Substrate) yang terlihat pada pemetaan memori
 * proses. Ini sinyal terkuat di kategori hook; dipakai bersama `hook.frida_threads`
 * dan check native.
 */
class FridaMapsCheck(private val proc: ProcProbe) : RaspCheck {

    override val id = "hook.maps_artifacts"
    override val category = Category.HOOK
    override val cost = Cost.MEDIUM

    override fun run(ctx: RaspContext): CheckResult {
        val maps = proc.selfMaps()
            ?: return CheckResult.Unknown("tidak bisa membaca /proc/self/maps")

        // Satu kali lowercase lalu pencarian indexOf native yang cepat. Jalur
        // contains(ignoreCase = true) terbukti terlalu lambat saat cold start (per-karakter
        // dibandingkan untuk setiap posisi di string multi-megabyte).
        val haystack = maps.lowercase()
        val matches = MARKERS.filter { marker -> marker in haystack }
        return if (matches.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(matches.map { Evidence(id, CONFIDENCE, "marker:$it") })
        }
    }

    companion object {
        const val CONFIDENCE = 0.85f

        val MARKERS = listOf("frida", "xposed", "substrate", "lsposed", "libgum")
    }
}
