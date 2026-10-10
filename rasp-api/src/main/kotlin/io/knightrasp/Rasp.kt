package io.knightrasp

import android.app.Application
import io.knightrasp.config.RaspConfig
import io.knightrasp.model.KeyAttestationCallback
import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.model.Trigger
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Public facade of the KnightRASP SDK.
 *
 * All methods are safe to call from the main thread and never throw exceptions to
 * the caller; failures are reported via [RaspListener.onError].
 *
 * The runtime is attached automatically by the aggregate `io.knightrasp:rasp` module (via
 * a ContentProvider) before `Application.onCreate` runs. If the app uses only
 * `rasp-api` without the aggregate module, the [init] call reports a
 * `NOT_INITIALIZED` error and does nothing (fail-open).
 */
object Rasp {
    @Volatile
    private var runtime: RaspRuntime? = null

    private val listeners = CopyOnWriteArrayList<RaspListener>()

    /**
     * Attaches the runtime to the facade. Called automatically by the `rasp` aggregate module.
     * Call manually only when integrating the modules separately.
     */
    @JvmStatic
    fun attachRuntime(runtime: RaspRuntime) {
        this.runtime = runtime
        listeners.forEach(runtime::addListener)
    }

    /** Initializes the SDK. Call once in `Application.onCreate`. */
    @JvmStatic
    fun init(app: Application, config: RaspConfig) {
        val runtime = runtime
        if (runtime == null) {
            reportError(
                RaspError(
                    RaspError.Code.NOT_INITIALIZED,
                    "No RASP runtime. Add the io.knightrasp:rasp dependency.",
                )
            )
            return
        }
        runtime.init(app, config)
    }

    /** Runs an asynchronous scan; the result is delivered to listeners. */
    @JvmStatic
    @JvmOverloads
    fun scan(trigger: Trigger = Trigger.ON_DEMAND) {
        val runtime = runtime
        if (runtime == null) {
            reportError(RaspError(RaspError.Code.NOT_INITIALIZED, "RASP has no runtime yet."))
            return
        }
        runtime.scan(trigger)
    }

    /** Synchronous scan with a timeout, for gates at critical points (login, transfer). */
    @JvmStatic
    @JvmOverloads
    fun scanSync(timeoutMs: Long = 2_000L): ThreatAssessment {
        val runtime = runtime
        if (runtime == null) {
            reportError(RaspError(RaspError.Code.NOT_INITIALIZED, "RASP has no runtime yet."))
            return ThreatAssessment.unknown(System.currentTimeMillis())
        }
        return runtime.scanSync(timeoutMs)
    }

    @JvmStatic
    fun addListener(listener: RaspListener) {
        listeners.addIfAbsent(listener)
        runtime?.addListener(listener)
    }

    /**
     * Requests hardware-backed key attestation (AndroidKeyStore, TEE/StrongBox).
     * Send the certificate chain to your backend and verify it against Google's
     * root certificates; do not trust the client-side parsed fields alone.
     * [callback] is invoked on the main thread (null result = unavailable/failed).
     */
    @JvmStatic
    @JvmOverloads
    fun requestKeyAttestation(nonce: String? = null, callback: KeyAttestationCallback) {
        val runtime = runtime
        if (runtime == null) {
            reportError(RaspError(RaspError.Code.NOT_INITIALIZED, "RASP has no runtime attached."))
            callback.onResult(null)
            return
        }
        runtime.requestKeyAttestation(nonce, callback)
    }

    @JvmStatic
    fun removeListener(listener: RaspListener) {
        listeners.remove(listener)
        runtime?.removeListener(listener)
    }

    /** Stops the runtime: cancels running scans and releases lifecycle callbacks. */
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
