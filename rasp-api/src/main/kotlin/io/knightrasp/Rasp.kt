package io.knightrasp

import android.app.Application
import io.knightrasp.config.RaspConfig
import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.model.Trigger
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Facade publik SDK KnightRASP.
 *
 * Semua method aman dipanggil dari main thread dan tidak pernah melempar exception ke
 * pemanggil; kegagalan dilaporkan melalui [RaspListener.onError].
 *
 * Runtime di-attach otomatis oleh modul agregat `io.knightrasp:rasp` (lewat
 * ContentProvider) sebelum `Application.onCreate` berjalan. Bila aplikasi hanya
 * memakai `rasp-api` tanpa modul agregat, panggilan [init] akan melaporkan error
 * `NOT_INITIALIZED` dan tidak melakukan apa pun (fail-open).
 */
object Rasp {
    @Volatile
    private var runtime: RaspRuntime? = null

    private val listeners = CopyOnWriteArrayList<RaspListener>()

    /**
     * Menyambungkan runtime ke facade. Dipanggil otomatis oleh modul agregat `rasp`.
     * Hanya panggil manual bila mengintegrasikan modul-modul secara terpisah.
     */
    @JvmStatic
    fun attachRuntime(runtime: RaspRuntime) {
        this.runtime = runtime
        listeners.forEach(runtime::addListener)
    }

    /** Inisialisasi SDK. Panggil sekali di `Application.onCreate`. */
    @JvmStatic
    fun init(app: Application, config: RaspConfig) {
        val runtime = runtime
        if (runtime == null) {
            reportError(
                RaspError(
                    RaspError.Code.NOT_INITIALIZED,
                    "Tidak ada RASP runtime. Tambahkan dependency io.knightrasp:rasp.",
                )
            )
            return
        }
        runtime.init(app, config)
    }

    /** Menjalankan scan asinkron; hasil dikirim ke listener. */
    @JvmStatic
    @JvmOverloads
    fun scan(trigger: Trigger = Trigger.ON_DEMAND) {
        val runtime = runtime
        if (runtime == null) {
            reportError(RaspError(RaspError.Code.NOT_INITIALIZED, "RASP belum memiliki runtime."))
            return
        }
        runtime.scan(trigger)
    }

    /** Scan sinkron dengan timeout, untuk gate di titik kritis (login, transfer). */
    @JvmStatic
    @JvmOverloads
    fun scanSync(timeoutMs: Long = 2_000L): ThreatAssessment {
        val runtime = runtime
        if (runtime == null) {
            reportError(RaspError(RaspError.Code.NOT_INITIALIZED, "RASP belum memiliki runtime."))
            return ThreatAssessment.unknown(System.currentTimeMillis())
        }
        return runtime.scanSync(timeoutMs)
    }

    @JvmStatic
    fun addListener(listener: RaspListener) {
        listeners.addIfAbsent(listener)
        runtime?.addListener(listener)
    }

    @JvmStatic
    fun removeListener(listener: RaspListener) {
        listeners.remove(listener)
        runtime?.removeListener(listener)
    }

    /** Menghentikan runtime: membatalkan scan yang berjalan dan melepas lifecycle callback. */
    @JvmStatic
    fun shutdown() {
        runtime?.shutdown()
    }

    private fun reportError(error: RaspError) {
        listeners.forEach { listener ->
            runCatching { listener.onError(error) }
        }
    }
}
