package io.knightrasp

import android.app.Application
import io.knightrasp.config.RaspConfig
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.model.Trigger

/**
 * Kontrak internal antara facade [Rasp] dan mesin RASP.
 *
 * Implementasi default disediakan oleh `rasp-core` dan di-attach oleh modul agregat
 * `rasp`. Jangan bergantung pada interface ini dari kode aplikasi; API publik ada
 * di [Rasp].
 */
interface RaspRuntime {
    fun init(app: Application, config: RaspConfig)

    fun scan(trigger: Trigger)

    fun scanSync(timeoutMs: Long): ThreatAssessment

    fun addListener(listener: RaspListener)

    fun removeListener(listener: RaspListener)

    fun shutdown()
}
