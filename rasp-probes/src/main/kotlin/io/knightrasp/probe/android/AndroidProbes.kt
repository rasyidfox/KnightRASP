package io.knightrasp.probe.android

import android.content.Context
import io.knightrasp.probe.FileProbe
import io.knightrasp.probe.NativeProbe
import io.knightrasp.probe.PackageProbe
import io.knightrasp.probe.ProcProbe
import io.knightrasp.probe.Probes
import io.knightrasp.probe.SettingsProbe
import io.knightrasp.probe.SystemProbe

/**
 * Rangkaian probe produksi. Semua probe bersifat stateless dan aman dipakai lintas thread.
 *
 * @param native probe native dari modul `rasp-native`; null bila library native tidak
 *   disertakan (varian tanpa NDK) — check yang bergantung padanya akan melaporkan Unknown.
 */
class AndroidProbes(
    context: Context,
    override val native: NativeProbe? = null,
) : Probes {

    private val appContext: Context = context.applicationContext ?: context

    override val file: FileProbe = AndroidFileProbe()
    override val proc: ProcProbe = AndroidProcProbe()
    override val packages: PackageProbe = AndroidPackageProbe(appContext)
    override val settings: SettingsProbe = AndroidSettingsProbe(appContext)
    override val system: SystemProbe = AndroidSystemProbe(appContext)
}
