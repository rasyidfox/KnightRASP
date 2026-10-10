package io.knightrasp

import android.app.Application
import io.knightrasp.config.RaspConfig
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.model.Trigger

/**
 * Internal contract between the [Rasp] facade and the RASP engine.
 *
 * The default implementation is provided by `rasp-core` and attached by the aggregate
 * `rasp` module. Do not depend on this interface from app code; the public API is
 * in [Rasp].
 */
interface RaspRuntime {
    fun init(app: Application, config: RaspConfig)

    fun scan(trigger: Trigger)

    fun scanSync(timeoutMs: Long): ThreatAssessment

    fun addListener(listener: RaspListener)

    fun removeListener(listener: RaspListener)

    fun shutdown()
}
