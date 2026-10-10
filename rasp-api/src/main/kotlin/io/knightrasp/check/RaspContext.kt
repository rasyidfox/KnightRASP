package io.knightrasp.check

import io.knightrasp.config.RaspConfig
import io.knightrasp.probe.Probes

/** Context passed to each [RaspCheck] when it runs. */
interface RaspContext {
    val config: RaspConfig

    /** OS access. The only channel checks are allowed to use. */
    val probes: Probes

    val packageName: String

    val nowMs: Long
}
