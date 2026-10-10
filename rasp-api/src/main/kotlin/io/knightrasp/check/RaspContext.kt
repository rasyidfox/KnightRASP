package io.knightrasp.check

import io.knightrasp.config.RaspConfig
import io.knightrasp.probe.Probes

/** Konteks yang diterima setiap [RaspCheck] saat dijalankan. */
interface RaspContext {
    val config: RaspConfig

    /** Akses ke OS. Satu-satunya jalur yang boleh dipakai check. */
    val probes: Probes

    val packageName: String

    val nowMs: Long
}
