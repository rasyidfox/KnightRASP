package io.knightrasp.probe.android

import android.content.Context
import io.knightrasp.probe.AttestationProbe
import io.knightrasp.probe.FileProbe
import io.knightrasp.probe.NativeProbe
import io.knightrasp.probe.PackageProbe
import io.knightrasp.probe.ProcProbe
import io.knightrasp.probe.Probes
import io.knightrasp.probe.SettingsProbe
import io.knightrasp.probe.SystemProbe

/**
 * Production probe set. All probes are stateless and safe to use across threads.
 *
 * @param native native probe from the `rasp-native` module; null when the native library
 *   is not included (NDK-less variant) — checks that depend on it report Unknown.
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
    override val attestation: AttestationProbe = AndroidAttestationProbe()
}
